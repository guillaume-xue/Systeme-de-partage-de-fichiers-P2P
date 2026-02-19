package transport

import (
	"context"
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
	structureCache     map[[32]byte][]byte
	structureCacheSize int64 // Taille actuelle en bytes
	structureCacheMu   sync.RWMutex

	// Stats
	savedFiles int
	savedBytes int64
	statsMu    sync.Mutex

	// RTT estimation (RFC 6298) + contrôle de congestion
	srtt     time.Duration // Moyenne lissée du RTT
	rttvar   time.Duration // Variance lissée du RTT
	rto      time.Duration // Timeout de retransmission dynamique
	rttInit  bool          // Premier échantillon RTT reçu ?
	ssthresh int           // Seuil slow-start / congestion avoidance

	// Lifecycle
	wg          sync.WaitGroup
	unsubscribe func()
	running     bool
	// Channel pour signaler la fin
	done chan struct{}

	// Semaphore pour limiter les goroutines de processing
	processorSem chan struct{}
	// Compteur de goroutines actives dans le processor
	processingCount int
	processingMu    sync.Mutex
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

		// RTT init
		rto:      config.GlobalConfig.Network.TimeoutDownload, // RTO initial = timeout config
		ssthresh: config.GlobalConfig.Network.MaxWindowSize,   // Slow-start jusqu'à maxWindow

		inflight: make(map[[32]byte]time.Time),
		retries:  make(map[[32]byte]int),

		workQueue:  make(chan task, protocol.MaxQueueSize),
		responseCh: make(chan [32]byte, protocol.MaxQueueSize),

		pathMap:        make(map[[32]byte]string),
		bigFiles:       make(map[[32]byte]string),
		structureCache: make(map[[32]byte][]byte),

		running:      true,
		done:         make(chan struct{}),
		processorSem: make(chan struct{}, config.GlobalConfig.Network.ProcessorWorkers),
	}
}

// DownloadToDisk télécharge l'arborescence complète et la sauvegarde sur disque
func (d *DiskDownloader) DownloadToDisk(ctx context.Context, rootHash [32]byte) error {
	// 1. Setup dossier
	if err := os.MkdirAll(d.outputDir, 0755); err != nil {
		return fmt.Errorf("mkdir fail: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 2. Abonnement aux events UDP
	// On utilise le hash comme ID
	subID := fmt.Sprintf("dl_%d", rootHash)
	d.unsubscribe = d.server.DatumDispatcher.Subscribe(subID, d.onDatumReceived)

	fmt.Printf("📥 Start DL -> %s (Root: %x...)\n", d.outputDir, rootHash)

	// 3. Démarrage workers
	d.wg.Add(3)
	go d.senderLoop()
	go d.processorLoop()
	go d.monitorLoop()

	// 4. On lance la machine avec la première tâche
	d.workQueue <- task{hash: rootHash, path: "__ROOT__"} // Marker spécial, utile pour différencier root ou autre

	// 5. Attente passive
	select {
	case <-d.done:
	case <-ctx.Done():
		d.stop()
		os.RemoveAll(d.tempDir)
		return ctx.Err()
	}

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

	// Nettoyer les requêtes en attente pour éviter les entrées orphelines
	d.pendingMu.Lock()
	for hash := range d.inflight {
		d.server.UnregisterDatumRequest(hash, d.peer)
	}
	d.pendingMu.Unlock()
}

// Callback UDP
func (d *DiskDownloader) onDatumReceived(hash [32]byte, data []byte) {
	// retirer de inflight tds pour éviter les faux timeouts
	d.pendingMu.Lock()
	start, wasInflight := d.inflight[hash]
	wasRetried := d.retries[hash] > 0 // Algorithme de Karn
	d.pendingMu.Unlock()

	if wasInflight {
		responseTime := time.Since(start)
		// Karn : pas de mise à jour RTT sur retransmission
		if !wasRetried {
			d.updateRTTAndWindow(responseTime)
		} else {
			d.growWindowOnly(responseTime)
		}
		d.removeFromInflight(hash)
	}

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

	// Signal garanti : goroutine pour ne pas bloquer le callback UDP
	// et ne jamais perdre de signal (sinon enfants jamais explorés)
	go func() { d.responseCh <- hash }()
}

// writeTempChunk écrit un chunk sur le disque dans le dossier temp
func (d *DiskDownloader) writeTempChunk(hash [32]byte, data []byte) error {
	// Ici on écrit tout le data (header inclu).
	return os.WriteFile(d.getTempChunkPath(hash), data, 0644)
}

// WORKER 1 : Envoie les requêtes
func (d *DiskDownloader) senderLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for d.running {
		d.pendingMu.Lock()
		canSend := len(d.inflight) < d.window
		d.pendingMu.Unlock()

		if !canSend {
			select {
			case <-ticker.C:
				continue
			case <-d.done:
				return
			}
		}

		// Récup prochaine tâche
		select {
		case tache, ok := <-d.workQueue:
			if !ok {
				return
			}

			if d.hasDatum(tache.hash) {
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

			d.server.RegisterDatumRequest(tache.hash, d.peer)
			SendDatumRequest(d.server.Conn, d.peer, tache.hash)
		case <-d.done:
			return
		}
	}
}

func (d *DiskDownloader) hasTempChunk(hash [32]byte) bool {
	_, err := os.Stat(d.getTempChunkPath(hash))
	return err == nil
}

// getTempChunkPath retourne le chemin d'un chunk temporaire
func (d *DiskDownloader) getTempChunkPath(hash [32]byte) string {
	return filepath.Join(d.tempDir, fmt.Sprintf("%x", hash))
}

// readDatum lit un datum depuis la RAM (structure) ou le disque (chunk)
func (d *DiskDownloader) readDatum(hash [32]byte) ([]byte, bool) {
	// 1. Essayer RAM
	d.structureCacheMu.RLock()
	data, inRam := d.structureCache[hash]
	d.structureCacheMu.RUnlock()

	if inRam {
		return data, true
	}

	// 2. Essayer disque
	data, err := os.ReadFile(d.getTempChunkPath(hash))
	if err != nil {
		return nil, false
	}

	return data, true
}

// hasDatum vérifie si un datum existe en RAM ou sur disque
func (d *DiskDownloader) hasDatum(hash [32]byte) bool {
	// Check RAM
	d.structureCacheMu.RLock()
	_, inRam := d.structureCache[hash]
	d.structureCacheMu.RUnlock()

	if inRam {
		return true
	}

	// Check Disque
	return d.hasTempChunk(hash)
}

// recordSuccess enregistre un fichier sauvegardé avec sa taille
func (d *DiskDownloader) recordSuccess(size int64) {
	d.statsMu.Lock()
	d.savedFiles++
	d.savedBytes += size
	d.statsMu.Unlock()
}

// updateRTTAndWindow met à jour le RTT (RFC 6298) et ajuste la fenêtre.
func (d *DiskDownloader) updateRTTAndWindow(sample time.Duration) {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	if !d.rttInit {
		d.srtt = sample
		d.rttvar = sample / 2
		d.rttInit = true
	} else {
		diff := d.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		d.rttvar = (3*d.rttvar + diff) / 4 // β = 1/4
		d.srtt = (7*d.srtt + sample) / 8   // α = 1/8
	}

	// RTO = SRTT + 4 * RTTVAR, borné [50ms, timeout]
	d.rto = min(max(d.srtt+4*d.rttvar, 50*time.Millisecond), d.timeout)

	// Fenêtre : grandir si latence ≤ moyenne
	if sample <= d.srtt && d.window < d.maxWindow {
		if d.window < d.ssthresh {
			d.window += 2 // Slow Start
		} else {
			d.window++ // Congestion Avoidance
		}
		if d.window > d.maxWindow {
			d.window = d.maxWindow
		}
	}
}

// growWindowOnly ajuste la fenêtre sans toucher au RTT (Karn : paquet retransmis)
func (d *DiskDownloader) growWindowOnly(sample time.Duration) {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	if !d.rttInit {
		return
	}

	if sample <= d.srtt && d.window < d.maxWindow {
		if d.window < d.ssthresh {
			d.window += 2
		} else {
			d.window++
		}
		if d.window > d.maxWindow {
			d.window = d.maxWindow
		}
	}
}

// removeFromInflight retire un hash de la liste inflight et retourne son timestamp
func (d *DiskDownloader) removeFromInflight(hash [32]byte) time.Time {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	start := d.inflight[hash]
	delete(d.inflight, hash)
	delete(d.retries, hash)
	return start
}

// getCompletionStatus retourne les compteurs pour la détection de fin
func (d *DiskDownloader) getCompletionStatus() (inflight, queued, response, processing int) {
	d.pendingMu.Lock()
	inflight = len(d.inflight)
	queued = len(d.workQueue)
	response = len(d.responseCh)
	d.pendingMu.Unlock()

	d.processingMu.Lock()
	processing = d.processingCount
	d.processingMu.Unlock()

	return
}

// isDownloadComplete vérifie si le téléchargement est terminé
func (d *DiskDownloader) isDownloadComplete() bool {
	inflight, queued, response, processing := d.getCompletionStatus()
	return inflight == 0 && queued == 0 && response == 0 && processing == 0
}

// getStats retourne les statistiques de téléchargement
func (d *DiskDownloader) getStats() (files int, bytes int64) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	return d.savedFiles, d.savedBytes
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
		// Acquérir le semaphore (ou attendre qu'un slot se libère)
		d.processorSem <- struct{}{}

		// Incrémenter le compteur de processing actif
		d.processingMu.Lock()
		d.processingCount++
		d.processingMu.Unlock()

		// Traiter en parallèle
		go func(h [32]byte) {
			defer func() {
				<-d.processorSem // Libérer le semaphore
				d.processingMu.Lock()
				d.processingCount--
				d.processingMu.Unlock()
			}()

			path := d.getPath(h)
			d.processDatum(h, path)
		}(hash)
	}

	// Attendre que tous les processing en cours se terminent
	for i := 0; i < cap(d.processorSem); i++ {
		d.processorSem <- struct{}{}
	}
}

// WORKER 3 : Gère les timeouts
func (d *DiskDownloader) monitorLoop() {
	defer d.wg.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		inflight, queued, response, processing := d.getCompletionStatus()
		d.pendingMu.Lock()
		windowSize := d.window
		rtt := d.srtt
		rto := d.rto
		d.pendingMu.Unlock()

		// Affichage des stats
		savedFiles, savedBytes := d.getStats()

		fmt.Printf("\r%-100s\r", "") // Nettoyer la ligne
		fmt.Printf("💾 DL: (%d fichiers, %s) | Vol: %d | File: %d | Fen: %d | RTT: %s | RTO: %s",
			savedFiles, utils.FormatBytesInt64(savedBytes), inflight, queued, windowSize,
			rtt.Round(time.Millisecond), rto.Round(time.Millisecond))

		// Logique de fin
		if inflight == 0 && queued == 0 && response == 0 && processing == 0 {
			// Petite vérif double
			time.Sleep(200 * time.Millisecond)
			if d.isDownloadComplete() {
				fmt.Println()
				close(d.done)
				return
			}
		}

		// Gestion des timeouts
		retryList := d.handleTimeouts()

		// Retransmission
		for _, hash := range retryList {
			// Vérifier si le datum a été reçu entre le timeout et le retry
			if d.hasDatum(hash) {
				d.removeFromInflight(hash)
				d.server.UnregisterDatumRequest(hash, d.peer)
				continue
			}
			// Re-enregistrer avant d'envoyer (la réponse précédente a pu
			// consommer l'enregistrement entre le unlock et maintenant)
			d.server.RegisterDatumRequest(hash, d.peer)
			SendDatumRequest(d.server.Conn, d.peer, hash)
		}
	}
}

// handleTimeouts gère les timeouts et retourne la liste des hashs à retransmettre
func (d *DiskDownloader) handleTimeouts() [][32]byte {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	now := time.Now()
	timeoutCount := 0
	var retryList [][32]byte

	for hash, sentAt := range d.inflight {
		if now.Sub(sentAt) > d.rto {
			timeoutCount++
			d.retries[hash]++
			if d.retries[hash] > 3 {
				fmt.Printf("\n⚠️ Abandon définitif chunk %x\n", hash)
				delete(d.inflight, hash)
				delete(d.retries, hash)
				d.server.UnregisterDatumRequest(hash, d.peer)
			} else {
				retryList = append(retryList, hash)
				d.inflight[hash] = now
			}
		}
	}

	// Multiplicative decrease + back-off RTO
	if timeoutCount > 0 {
		d.ssthresh = utils.MaxInt(d.window/2, d.minWindow)
		d.window = utils.MaxInt(d.window/2, d.minWindow)
		d.rto = min(d.rto*2, d.timeout)
	}

	return retryList
}

// Traitement d'un datum reçu
func (d *DiskDownloader) processDatum(hash [32]byte, destPath string) {
	data, found := d.readDatum(hash)
	if !found {
		return // Pas trouvé, on attendra que le receiver le reçoive
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
				d.recordSuccess(int64(len(content)))
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
			d.recordSuccess(size)
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
	chunkPath := d.getTempChunkPath(hash)
	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		return 0, fmt.Errorf("chunk manquant: %x", hash)
	}

	// Supprimer le chunk après lecture pour libérer l'espace disque
	defer os.Remove(chunkPath)

	_, content := merkle.ParseDatum(chunkData)

	n, err := writer.Write(content)
	return int64(n), err
}
