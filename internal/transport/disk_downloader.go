package transport

import (
	"fmt"
	"main/internal/config"
	"main/internal/merkle"
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
// Gère la window size pour ne pas tuer le réseau UDP
type DiskDownloader struct {
	server    *Server
	peer      *net.UDPAddr
	outputDir string

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
	// On stocke les chemins des fichiers "Big" pour les reconstruire à la fin
	bigFiles   map[[32]byte]string
	bigFilesMu sync.Mutex

	// Cache temporaire pour les noeuds intermédiaires (BigNodes, Directories)
	// Les chunks de fichiers, eux, vont direct sur le disque.
	cache   map[[32]byte][]byte
	cacheMu sync.RWMutex

	// Stats
	savedFiles int
	savedBytes int64

	// Lifecycle
	wg          sync.WaitGroup
	unsubscribe func()
	running     bool
}

func NewDiskDownloader(server *Server, peer *net.UDPAddr, output string) *DiskDownloader {
	return &DiskDownloader{
		server:    server,
		peer:      peer,
		outputDir: output,

		// Params fenêtre
		window:    config.GlobalConfig.Network.InitialWindow,
		maxWindow: config.GlobalConfig.Network.MaxWindowSize,
		minWindow: config.GlobalConfig.Network.MinWindowSize,
		timeout:   config.GlobalConfig.Network.TimeoutDownload,

		inflight: make(map[[32]byte]time.Time),
		retries:  make(map[[32]byte]int),

		workQueue:  make(chan task, 10000), // Buffer large pour ne pas bloquer (valeur arbitraire)
		responseCh: make(chan [32]byte, 100),

		pathMap:  make(map[[32]byte]string),
		bigFiles: make(map[[32]byte]string),
		cache:    make(map[[32]byte][]byte),

		running: true,
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

	// 4. On lance la machine avec la racine
	fmt.Printf("📥 Start DL -> %s (Root: %x...)\n", d.outputDir, rootHash[:6])

	// On doit d'abord télécharger le datum pour connaître son type
	// On commence par demander le hash
	d.workQueue <- task{hash: rootHash, path: "__ROOT__"} // Marker spécial, utile pour différencier root ou autre

	// 5. Attente
	d.waitFinish()

	// 6. Reconstruction finale (Assemblage des gros fichiers)
	d.finalizeBigFiles()

	// 7. Cleanup
	d.stop()

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

// waitFinish boucle tant qu'il y a du boulot
func (d *DiskDownloader) waitFinish() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		<-ticker.C

		d.pendingMu.Lock()
		inflightCount := len(d.inflight)
		d.pendingMu.Unlock()

		// Si plus rien en cours, plus rien dans la queue, on suppose que c'est fini
		if inflightCount == 0 && len(d.workQueue) == 0 {
			// Petite pause de sécurité pour être sûr qu'un process en cours n'ajoute pas un truc
			time.Sleep(500 * time.Millisecond)
			if len(d.inflight) == 0 && len(d.workQueue) == 0 {
				break
			}
		}
	}
}

// Callback appelé par le Dispatcher UDP
func (d *DiskDownloader) onDatumReceived(hash [32]byte, data []byte) {
	// On stocke d'abord en cache
	d.cacheMu.Lock()
	d.cache[hash] = data
	d.cacheMu.Unlock()

	// On signale au processeur
	// Select non-bloquant pour ne pas freezer le thread réseau UDP si le channel est plein
	select {
	case d.responseCh <- hash:
	default:
		// Drop signal, le timeout s'en chargera ou le prochain packet
	}
}

// WORKER 1 : Envoie les requêtes 
func (d *DiskDownloader) senderLoop() {
	defer d.wg.Done()

	for d.running {
		// Vérif fenêtre
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
		} // Channel fermé

		// Check si déjà reçu (cache)
		d.cacheMu.RLock()
		_, gotIt := d.cache[tache.hash]
		d.cacheMu.RUnlock()

		if gotIt {
			// On le traite direct comme si on venait de le recevoir
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
			// Calcul pour ajuster fenêtre
			if time.Since(start) < d.timeout/2 {
				if d.window < d.maxWindow {
					d.window++
				}
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
		now := time.Now()

		d.pendingMu.Lock()
		for hash, sentAt := range d.inflight {
			if now.Sub(sentAt) > d.timeout {
				// Timeout !
				d.retries[hash]++
				if d.retries[hash] > 5 {
					// Trop d'échecs, on abandonne ce chunk
					fmt.Printf("⚠️ Give up on %x\n", hash)
					delete(d.inflight, hash)
				} else {
					// Retry
					d.inflight[hash] = now // Reset timer
					// Congestion control: on divise la fenêtre par 2
					d.window = utils.MaxInt(d.window/2, d.minWindow)

					// Renvoi
					go SendDatumRequest(d.server.Conn, d.peer, hash)
				}
			}
		}
		d.pendingMu.Unlock()
	}
}

// Traitement d'un datum reçu
func (d *DiskDownloader) processDatum(hash [32]byte, destPath string) {
	d.cacheMu.RLock()
	data, exists := d.cache[hash]
	d.cacheMu.RUnlock()

	if !exists {
		return
	}

	typ, content := merkle.ParseDatum(data)

	// Cas spécial si c'est le hash de départ (marqué __ROOT__), on détermine le chemin approprié
	if destPath == "__ROOT__" {
		// Déterminer le nom de fichier/dossier selon le type
		if typ == merkle.TypeDirectory || typ == merkle.TypeBigDirectory {
			// C'est un dossier, on crée un sous-dossier avec le hash comme nom
			// L'arborescence interne gardera les noms corrects car ils sont dans les Directory entries
			destPath = filepath.Join(d.outputDir, fmt.Sprintf("dir_%x", hash))
		} else {
			// C'est un fichier, on crée un nom de fichier avec le hash
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
			// Calcul du chemin enfant
			childPath := ""
			if destPath != "" {
				childPath = filepath.Join(destPath, merkle.GetEntryName(e))
			}
			// On ajoute à la file
			d.workQueue <- task{hash: e.Hash, path: childPath}
		}

	case merkle.TypeBigDirectory:
		// Un gros dossier, c'est juste une liste de hashs qui pointent vers des Directory partiels
		hashes := merkle.ParseBigHashes(content)
		for _, hash := range hashes {
			// On propage le même path (c'est le même dossier, juste fragmenté)
			d.workQueue <- task{hash: hash, path: destPath}
		}

	case merkle.TypeChunk:
		if destPath != "" {
			fmt.Printf("💾 Sauvegarde chunk -> %s (%d bytes)\n", destPath, len(content))
			err := os.WriteFile(destPath, content, 0644)
			if err == nil {
				d.savedFiles++
				d.savedBytes += int64(len(content))
			} else {
				fmt.Printf("❌ Erreur écriture: %v\n", err)
			}
		}

	case merkle.TypeBig:
		// Fichier fragmenté. On ne peut pas écrire les bouts en vrac car on ne connait pas l'ordre
		// sans parser tout l'arbre.
		// On télécharge tout en cache, et on note qu'il faudra le reconstruire à la fin.

		// 1. On note le hash et le path pour plus tard
		if destPath != "" {
			fmt.Printf("📦 Fichier fragmenté détecté: %s\n", destPath)
			d.bigFilesMu.Lock()
			d.bigFiles[hash] = destPath
			d.bigFilesMu.Unlock()
		}

		// 2. On demande les enfants (sans path, car ce sont des bouts bruts)
		hashes := merkle.ParseBigHashes(content)
		for _, hash := range hashes {
			d.workQueue <- task{hash: hash, path: ""}
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

	fmt.Printf("🔨 Reconstruction de %d gros fichiers...\n", len(d.bigFiles))

	for hash, path := range d.bigFiles {
		fmt.Printf("📦 Reconstruction %s...\n", filepath.Base(path))
		content, ok := d.reconstruct(hash)
		if ok {
			err := os.WriteFile(path, content, 0644)
			if err == nil {
				d.savedFiles++
				d.savedBytes += int64(len(content))
				fmt.Printf("✅ %s (%s)\n", filepath.Base(path), utils.FormatBytesInt64(int64(len(content))))
			} else {
				fmt.Printf("❌ Erreur écriture %s: %v\n", filepath.Base(path), err)
			}
		} else {
			fmt.Printf("❌ Echec reconstruction %s (données manquantes)\n", filepath.Base(path))
		}
	}
}

// Reconstruction récursive depuis le cache RAM
func (d *DiskDownloader) reconstruct(hash [32]byte) ([]byte, bool) {
	d.cacheMu.RLock()
	data, ok := d.cache[hash]
	d.cacheMu.RUnlock()

	if !ok {
		return nil, false
	}

	typ, content := merkle.ParseDatum(data)

	if typ == merkle.TypeChunk {
		return content, true
	}

	if typ == merkle.TypeBig {
		var full []byte
		hashes := merkle.ParseBigHashes(content)
		for _, hash := range hashes {
			part, ok := d.reconstruct(hash)
			if !ok {
				return nil, false
			}
			full = append(full, part...)
		}
		return full, true
	}

	return nil, false
}
