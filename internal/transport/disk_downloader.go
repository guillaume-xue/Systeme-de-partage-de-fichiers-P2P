package transport

import (
	"fmt"
	"io"
	"main/internal/config"
	"main/internal/merkle"
	"main/internal/protocol"
	"main/internal/utils"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Task : un truc à faire
type task struct {
	hash [32]byte
	path string // vide si c'est juste un morceau intermédiaire
}

// DiskDownloader : Télécharge direct sur le disque
type DiskDownloader struct {
	server    *Server
	peer      *net.UDPAddr
	outputDir string
	tempDir   string // dossier pour les chunks temporaires

	// Flow Control
	window    int
	maxWindow int
	minWindow int
	timeout   time.Duration

	// État
	inflight  map[[32]byte]time.Time // Hash -> Timestamp d'envoi
	retries   map[[32]byte]int       // Hash -> Nombre d'essais
	pendingMu sync.Mutex             // Protège inflight et retries, et window

	// Files d'attente
	workQueue  chan task
	responseCh chan [32]byte // Signale qu'un hash est arrivé

	// Map pour se souvenir où écrire quoi
	pathMap   map[[32]byte]string
	pathMapMu sync.Mutex

	// Reconstruction
	bigFiles   map[[32]byte]string
	bigFilesMu sync.Mutex

	// Cache uniquement pour la STRUCTURE (BigNodes, Dirs).
	// Les données brutes (Chunks) vont dans tempDir.
	structureCache   map[[32]byte][]byte
	structureCacheMu sync.RWMutex

	// Stats
	savedFiles   int
	savedBytes   int64
	successCount int // Compteur de succès consécutifs
	failureCount int // Compteur d'échecs récents
	statsMu      sync.Mutex

	// Lifecycle
	wg          sync.WaitGroup
	unsubscribe func()
	running     bool
	// Channel pour signaler la fin
	done chan struct{}
}

func NewDiskDownloader(server *Server, peer *net.UDPAddr, output string) *DiskDownloader {
	// Création d'un dossier temporaire caché dans le dossier de destination
	tempDir := filepath.Join(output, ".tmp_chunks")
	os.MkdirAll(tempDir, 0755)

	return &DiskDownloader{
		server:    server,
		peer:      peer,
		outputDir: output,
		tempDir:   tempDir,

		// Params fenêtre
		window:    config.GlobalConfig.Network.InitialWindow,
		maxWindow: config.GlobalConfig.Network.MaxWindowSize,
		minWindow: config.GlobalConfig.Network.MinWindowSize,
		timeout:   config.GlobalConfig.Network.TimeoutDownload,

		inflight: make(map[[32]byte]time.Time),
		retries:  make(map[[32]byte]int),

		workQueue:  make(chan task, protocol.MaxQueueSize),
		responseCh: make(chan [32]byte, protocol.MaxQueueSize),

		pathMap:        make(map[[32]byte]string),
		bigFiles:       make(map[[32]byte]string),
		structureCache: make(map[[32]byte][]byte),

		running: true,
		done:    make(chan struct{}),
	}
}

// DownloadToDisk télécharge l'arborescence complète et la sauvegarde sur disque
func (d *DiskDownloader) DownloadToDisk(rootHash [32]byte) error {
	// 1. Setup dossier
	if err := os.MkdirAll(d.outputDir, 0755); err != nil {
		return fmt.Errorf("mkdir fail: %v", err)
	}

	// 2. Abonnement aux events UDP
	// On utilise un ID random pour éviter les collisions si on lance plusieurs DL
	subID := fmt.Sprintf("dl_%d", time.Now().UnixNano())
	d.unsubscribe = d.server.DatumDispatcher.Subscribe(subID, d.onDatumReceived)

	// 3. Démarrage workers
	d.wg.Add(3)
	go d.senderLoop()
	go d.processorLoop()
	go d.monitorLoop()

	fmt.Printf("📥 Start DL -> %s (Root: %x...)\n", d.outputDir, rootHash[:6])

	// 4. On lance la machine
	d.workQueue <- task{hash: rootHash, path: "__ROOT__"} // Marker spécial, utile pour différencier root ou autre

	// 5. Attente passive
	<-d.done

	// 6. Reconstruction finale (Assemblage des gros fichiers)
	d.finalizeBigFiles()

	// 7. Cleanup
	d.stop()

	// 8. Suppression du dossier temporaire
	os.RemoveAll(d.tempDir)

	fmt.Printf("\n✅ Fini ! %d fichiers, %s sur le disque.\n", d.savedFiles, utils.FormatBytesInt64(d.savedBytes))
	return nil
}

func (d *DiskDownloader) stop() {
	d.running = false
	if d.unsubscribe != nil {
		d.unsubscribe()
	}

	close(d.workQueue)
	close(d.responseCh)
	d.wg.Wait()
}

// Callback UDP
func (d *DiskDownloader) onDatumReceived(hash [32]byte, data []byte) {
	// On détermine si c'est un Chunk (Data) ou une Structure (Node)
	typ, _ := merkle.ParseDatum(data)

	if typ == merkle.TypeChunk {
		// ÉCRITURE DISQUE IMMÉDIATE (Pour économiser la RAM)
		// J'ai du implémenter ca à cause de gros fichiers qui saturent la RAM.
		// Gros téléchargement de 1 2Go a planté sinon.
		err := d.writeTempChunk(hash, data)
		if err != nil {
			fmt.Printf("❌ Erreur écriture temp chunk %x: %v\n", hash, err)
			return
		}
	} else {
		// stockage ram (Pour la structure de l'arbre)
		d.structureCacheMu.Lock()
		d.structureCache[hash] = data
		d.structureCacheMu.Unlock()
	}

	// Signal réception
	select {
	case d.responseCh <- hash:
	default:
	}
}

// writeTempChunk écrit un chunk sur le disque dans le dossier temp
func (d *DiskDownloader) writeTempChunk(hash [32]byte, data []byte) error {
	// On encode le hash en hex pour le nom de fichier
	filename := fmt.Sprintf("%x", hash)
	path := filepath.Join(d.tempDir, filename)

	// Ici on écrit tout le data (header inclu).
	return os.WriteFile(path, data, 0644)
}

// WORKER 1 : Envoie les requêtes
func (d *DiskDownloader) senderLoop() {
	defer d.wg.Done()
	for d.running {
		d.pendingMu.Lock()
		canSend := len(d.inflight) < d.window
		d.pendingMu.Unlock()

		if !canSend {
			time.Sleep(10 * time.Millisecond) // Petit wait si surcharge
			continue
		}

		// Récup prochaine tâche
		tache, ok := <-d.workQueue
		if !ok {
			return
		}

		// Check RAM Cache (Structure)
		d.structureCacheMu.RLock()
		_, inRam := d.structureCache[tache.hash]
		d.structureCacheMu.RUnlock()

		// Check Disk Cache (Chunk)
		inDisk := d.hasTempChunk(tache.hash)

		if inRam || inDisk {
			// Déjà là, on traite
			d.processDatum(tache.hash, tache.path)
			continue
		}

		// Check si déjà demandé (inflight)
		d.pendingMu.Lock()
		if _, sending := d.inflight[tache.hash]; sending {
			d.pendingMu.Unlock()
			continue
		}

		d.trackPath(tache.hash, tache.path)
		d.inflight[tache.hash] = time.Now()
		d.pendingMu.Unlock()

		SendDatumRequest(d.server.Conn, d.peer, tache.hash)
	}
}

func (d *DiskDownloader) hasTempChunk(hash [32]byte) bool {
	filename := fmt.Sprintf("%x", hash)
	path := filepath.Join(d.tempDir, filename)
	_, err := os.Stat(path)
	return err == nil
}

func (d *DiskDownloader) trackPath(hash [32]byte, p string) {
	if p == "" {
		return
	}
	d.pathMapMu.Lock()
	d.pathMap[hash] = p
	d.pathMapMu.Unlock()
}

func (d *DiskDownloader) getPath(hash [32]byte) string {
	d.pathMapMu.Lock()
	defer d.pathMapMu.Unlock()
	return d.pathMap[hash]
}

// WORKER 2 : Traite les réponses
func (d *DiskDownloader) processorLoop() {
	defer d.wg.Done()
	for hash := range d.responseCh {
		d.pendingMu.Lock()
		start, ok := d.inflight[hash]
		if ok {
			d.successCount++
			d.failureCount = 0

			// Augmenter la fenêtre seulement si réponse rapide
			// Si réponse lente, on est proche de la limite -> ne pas augmenter
			if time.Since(start) < d.timeout/2 && d.window < d.maxWindow {
				d.window++
			}
			delete(d.inflight, hash)
			delete(d.retries, hash) // Reset retry count
		}
		d.pendingMu.Unlock()
		path := d.getPath(hash) // Récup le path sauvegardé
		d.processDatum(hash, path)
	}
}

// WORKER 3 : Gère les timeouts
func (d *DiskDownloader) monitorLoop() {
	defer d.wg.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		d.pendingMu.Lock()
		inflightCount := len(d.inflight)
		queuedCount := len(d.workQueue)

		// Logique de fin
		if inflightCount == 0 && queuedCount == 0 {
			// Petite vérif double
			d.pendingMu.Unlock()
			time.Sleep(200 * time.Millisecond)
			d.pendingMu.Lock()
			if len(d.inflight) == 0 && len(d.workQueue) == 0 {
				d.pendingMu.Unlock()
				close(d.done)
				return
			}
		}

		// Gestion des timeouts
		now := time.Now()
		timeoutCount := 0
		var retryList [][32]byte

		for hash, sentAt := range d.inflight {
			if now.Sub(sentAt) > d.timeout {
				timeoutCount++
				d.retries[hash]++
				if d.retries[hash] > 3 {
					// Trop d'échecs, on abandonne ce chunk
					fmt.Printf("⚠️ Abandon définitif chunk %x\n", hash)
					delete(d.inflight, hash)
					delete(d.retries, hash)
				} else {
					// Retry - ajouter à la liste pour renvoyer après avoir relâché le lock
					retryList = append(retryList, hash)
					d.inflight[hash] = now // Reset timer
				}
			}
		}

		// Ajuster la fenêtre seulement si taux d'échec significatif
		// Ne pas pénaliser pour quelques timeouts isolés
		if timeoutCount > 0 {
			d.failureCount += timeoutCount
			d.successCount = 0

			// Diminuer la fenêtre seulement si échecs répétés
			// Seuil à 2 pour réagir plus vite
			if d.failureCount > 2 && d.window > d.minWindow {
				d.window = utils.MaxInt((d.window*3)/5, d.minWindow) // -40%
				d.failureCount = 0
			}
		}

		d.pendingMu.Unlock()

		// Retransmission
		for _, hash := range retryList {
			SendDatumRequest(d.server.Conn, d.peer, hash)
		}
	}
}

// Traitement d'un datum reçu
func (d *DiskDownloader) processDatum(hash [32]byte, destPath string) {
	// 1. Essayer de lire en RAM (Structure)
	d.structureCacheMu.RLock()
	data, inRam := d.structureCache[hash]
	d.structureCacheMu.RUnlock()

	// 2. Si pas en RAM, essayer sur disque (Chunk)
	if !inRam {
		var err error
		data, err = os.ReadFile(filepath.Join(d.tempDir, fmt.Sprintf("%x", hash)))
		if err != nil {
			return // Pas trouvé, on attendra que le receiver le reçoive
		}
	}

	typ, content := merkle.ParseDatum(data)

	// Gestion du nom ROOT
	if destPath == "__ROOT__" {
		if typ == merkle.TypeDirectory || typ == merkle.TypeBigDirectory {
			destPath = filepath.Join(d.outputDir, fmt.Sprintf("dir_%x", hash))
		} else {
			destPath = filepath.Join(d.outputDir, fmt.Sprintf("file_%x", hash))
		}
		fmt.Printf("📝 Type détecté: %d, destination: %s\n", typ, destPath)
	}

	switch typ {
	case merkle.TypeDirectory:
		if destPath != "" {
			os.MkdirAll(destPath, 0755)
		}
		entries := merkle.ParseDirectoryEntries(content)
		for _, e := range entries {
			childPath := ""
			if destPath != "" {
				childPath = filepath.Join(destPath, merkle.GetEntryName(e))
			}
			d.workQueue <- task{hash: e.Hash, path: childPath}
		}

	case merkle.TypeBigDirectory:
		hashes := merkle.ParseBigHashes(content)
		for _, hash := range hashes {
			d.workQueue <- task{hash: hash, path: destPath}
		}

	case merkle.TypeChunk:
		if destPath != "" {
			// On écrit le contenu
			err := os.WriteFile(destPath, content, 0644)
			if err == nil {
				d.statsMu.Lock()
				d.savedFiles++
				d.savedBytes += int64(len(content))
				d.statsMu.Unlock()
			}
		}

	case merkle.TypeBig:
		// Fichier fragmenté. On note pour reconstruction plus tard.
		if destPath != "" {
			d.bigFilesMu.Lock()
			d.bigFiles[hash] = destPath
			d.bigFilesMu.Unlock()
		}
		hashes := merkle.ParseBigHashes(content)
		for _, h := range hashes {
			d.workQueue <- task{hash: h, path: ""}
		}
	}
}

// Reconstruction finale des fichiers Type Big File
func (d *DiskDownloader) finalizeBigFiles() {
	d.bigFilesMu.Lock()
	defer d.bigFilesMu.Unlock()

	if len(d.bigFiles) == 0 {
		return
	}

	fmt.Printf("\n🔨 Reconstruction de %d gros fichiers...\n", len(d.bigFiles))

	for hash, path := range d.bigFiles {
		fmt.Printf("📦 Assemblage %s... ", filepath.Base(path))

		// Création du fichier final
		outFile, err := os.Create(path)
		if err != nil {
			fmt.Printf("❌ Erreur création: %v\n", err)
			continue
		}

		// Assemblage streamé
		size, err := d.assembleStream(hash, outFile)
		outFile.Close()

		if err == nil {
			d.statsMu.Lock()
			d.savedFiles++
			d.savedBytes += size
			d.statsMu.Unlock()
			fmt.Printf("✅ (%s)\n", utils.FormatBytesInt64(size))
		} else {
			fmt.Printf("❌ Echec: %v\n", err)
		}
	}
}

// assembleStream parcourt l'arbre et copie les chunks disque -> destination
// Retourne la taille totale écrite
func (d *DiskDownloader) assembleStream(hash [32]byte, writer io.Writer) (int64, error) {
	d.structureCacheMu.RLock()
	data, isStruct := d.structureCache[hash]
	d.structureCacheMu.RUnlock()

	if isStruct {
		// C'est un BigNode (intermédiaire)
		typ, content := merkle.ParseDatum(data)
		if typ != merkle.TypeBig {
			return 0, fmt.Errorf("structure invalide dans assembleStream (type %d)", typ)
		}

		var totalSize int64
		children := merkle.ParseBigHashes(content)
		for _, childHash := range children {
			written, err := d.assembleStream(childHash, writer)
			if err != nil {
				return totalSize, err
			}
			totalSize += written
		}
		return totalSize, nil
	}

	// Si pas en RAM, c'est un Chunk sur disque (Temp)
	chunkPath := filepath.Join(d.tempDir, fmt.Sprintf("%x", hash))
	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		return 0, fmt.Errorf("chunk manquant: %x", hash[:8])
	}

	_, content := merkle.ParseDatum(chunkData)

	n, err := writer.Write(content)
	return int64(n), err
}
