package transport

import (
	"fmt"
	"main/internal/merkle"
	"main/internal/utils"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DiskDownloader gère et télécharge l'arborescence Merkle directement sur disque
// Utilise une fenêtre glissante (sliding window) pour optimiser le débit
type DiskDownloader struct {
	server      *Server
	peerAddress *net.UDPAddr
	outputDir   string

	// Paramètres de la fenêtre glissante (congestion control AIMD)
	windowSize     int           // Taille actuelle de la fenêtre
	maxWindowSize  int           // Taille maximale de la fenêtre
	minWindowSize  int           // Taille minimale de la fenêtre
	requestTimeout time.Duration // Timeout pour une requête

	// Gestion des requêtes en cours
	pendingRequests   map[[32]byte]*diskPendingRequest
	pendingRequestsMu sync.Mutex
	responseChannel   chan [32]byte

	// Cache local des datums téléchargés
	datumCache   map[[32]byte][]byte
	datumCacheMu sync.RWMutex

	// Mapping hash → chemin de fichier
	hashToPath   map[[32]byte]string
	hashToPathMu sync.RWMutex

	// Fichiers Big à reconstruire après téléchargement
	bigFilesToReconstruct   map[[32]byte]string
	bigFilesToReconstructMu sync.Mutex

	// Compteur de traitements en cours
	activeProcessing   int
	activeProcessingMu sync.Mutex

	// Statistiques
	totalSent     int
	totalReceived int
	totalTimeouts int
	filesSaved    int
	bytesSaved    int64

	// File d'attente des téléchargements
	downloadQueue     []downloadTask
	downloadQueueMu   sync.Mutex
	downloadQueueCond *sync.Cond

	// Contrôle d'exécution
	isRunning bool
	waitGroup sync.WaitGroup
}

// diskPendingRequest représente une requête en attente de réponse
type diskPendingRequest struct {
	hash       [32]byte
	sentAt     time.Time
	retryCount int
}

// downloadTask représente un datum à télécharger
type downloadTask struct {
	hash     [32]byte
	filePath string
}

// NewDiskDownloader crée un nouveau gestionnaire de téléchargement
func NewDiskDownloader(server *Server, peerAddress *net.UDPAddr, outputDir string) *DiskDownloader {
	downloader := &DiskDownloader{
		server:                server,
		peerAddress:           peerAddress,
		outputDir:             outputDir,
		windowSize:            8,
		maxWindowSize:         64,
		minWindowSize:         1,
		requestTimeout:        2 * time.Second,
		pendingRequests:       make(map[[32]byte]*diskPendingRequest),
		responseChannel:       make(chan [32]byte, 200),
		datumCache:            make(map[[32]byte][]byte),
		hashToPath:            make(map[[32]byte]string),
		bigFilesToReconstruct: make(map[[32]byte]string),
		downloadQueue:         make([]downloadTask, 0),
		isRunning:             true,
	}
	downloader.downloadQueueCond = sync.NewCond(&downloader.downloadQueueMu)
	return downloader
}

// startWorkers démarre les goroutines de travail
func (d *DiskDownloader) startWorkers() {
	d.waitGroup.Add(3)
	go d.requestSenderLoop()
	go d.responseProcessorLoop()
	go d.timeoutMonitorLoop()
}

// stopWorkers arrête les goroutines de travail
func (d *DiskDownloader) stopWorkers() {
	d.isRunning = false
	d.downloadQueueCond.Broadcast()
	close(d.responseChannel)
	d.waitGroup.Wait()
}

// QueueDownload ajoute un hash à la file de téléchargement
func (d *DiskDownloader) QueueDownload(hash [32]byte, filePath string) {
	// Enregistrer le chemin de destination si spécifié
	if filePath != "" {
		d.hashToPathMu.Lock()
		d.hashToPath[hash] = filePath
		d.hashToPathMu.Unlock()
	}

	// Vérifier si déjà en cache
	d.datumCacheMu.RLock()
	_, alreadyCached := d.datumCache[hash]
	d.datumCacheMu.RUnlock()
	if alreadyCached {
		return
	}

	// Ajouter à la file d'attente
	d.downloadQueueMu.Lock()
	d.downloadQueue = append(d.downloadQueue, downloadTask{hash: hash, filePath: filePath})
	d.downloadQueueMu.Unlock()
	d.downloadQueueCond.Signal()
}

// NotifyReceived est appelé quand un datum est reçu du réseau
func (d *DiskDownloader) NotifyReceived(hash [32]byte, datum []byte) {
	// Stocker dans le cache
	d.datumCacheMu.Lock()
	d.datumCache[hash] = datum
	d.datumCacheMu.Unlock()

	// Notifier le processeur de réponses
	select {
	case d.responseChannel <- hash:
	case <-time.After(1 * time.Second):
	}
}

// WaitForCompletion attend que tous les téléchargements soient terminés
func (d *DiskDownloader) WaitForCompletion() {
	for {
		d.downloadQueueMu.Lock()
		queueLength := len(d.downloadQueue)
		d.downloadQueueMu.Unlock()

		d.pendingRequestsMu.Lock()
		pendingLength := len(d.pendingRequests)
		d.pendingRequestsMu.Unlock()

		d.activeProcessingMu.Lock()
		processingCount := d.activeProcessing
		d.activeProcessingMu.Unlock()

		if queueLength == 0 && pendingLength == 0 && processingCount == 0 {
			// Double vérification après un court délai
			time.Sleep(200 * time.Millisecond)

			d.downloadQueueMu.Lock()
			queueLength = len(d.downloadQueue)
			d.downloadQueueMu.Unlock()
			d.pendingRequestsMu.Lock()
			pendingLength = len(d.pendingRequests)
			d.pendingRequestsMu.Unlock()
			d.activeProcessingMu.Lock()
			processingCount = d.activeProcessing
			d.activeProcessingMu.Unlock()

			if queueLength == 0 && pendingLength == 0 && processingCount == 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// DownloadToDisk télécharge l'arborescence complète et la sauvegarde sur disque
func (d *DiskDownloader) DownloadToDisk(rootHash [32]byte) error {
	// Créer le répertoire de destination
	if err := os.MkdirAll(d.outputDir, 0755); err != nil {
		return fmt.Errorf("impossible de créer le répertoire: %w", err)
	}

	fmt.Printf("📥 Téléchargement vers %s\n", d.outputDir)

	// Démarrer les workers
	d.startWorkers()

	// Ajouter le hash racine à la file
	d.QueueDownload(rootHash, d.outputDir)

	// Afficher la progression
	go d.displayProgress()

	// Attendre la fin des téléchargements
	d.WaitForCompletion()

	// Reconstruire les fichiers Big
	d.reconstructBigFiles()

	// Arrêter les workers
	d.stopWorkers()

	// Afficher le résumé
	fmt.Printf("\n✅ Terminé: %d fichiers, %s\n", d.filesSaved, utils.FormatBytesInt64(d.bytesSaved))
	if d.totalTimeouts > 0 {
		fmt.Printf("⚠️  %d timeout(s)\n", d.totalTimeouts)
	}
	return nil
}

// requestSenderLoop envoie les requêtes DatumRequest
func (d *DiskDownloader) requestSenderLoop() {
	defer d.waitGroup.Done()

	for d.isRunning {
		// Attendre que la fenêtre soit disponible
		d.pendingRequestsMu.Lock()
		if len(d.pendingRequests) >= d.windowSize {
			d.pendingRequestsMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		d.pendingRequestsMu.Unlock()

		// Récupérer la prochaine tâche
		d.downloadQueueMu.Lock()
		for len(d.downloadQueue) == 0 && d.isRunning {
			d.downloadQueueCond.Wait()
		}
		if !d.isRunning {
			d.downloadQueueMu.Unlock()
			return
		}
		task := d.downloadQueue[0]
		d.downloadQueue = d.downloadQueue[1:]
		d.downloadQueueMu.Unlock()

		// Vérifier le cache
		d.datumCacheMu.RLock()
		_, alreadyCached := d.datumCache[task.hash]
		d.datumCacheMu.RUnlock()
		if alreadyCached {
			continue
		}

		// Vérifier si déjà en cours
		d.pendingRequestsMu.Lock()
		if _, isPending := d.pendingRequests[task.hash]; isPending {
			d.pendingRequestsMu.Unlock()
			continue
		}
		d.pendingRequests[task.hash] = &diskPendingRequest{hash: task.hash, sentAt: time.Now()}
		d.pendingRequestsMu.Unlock()

		// Envoyer la requête
		SendDatumRequest(d.server.Conn, d.peerAddress, task.hash)
		d.totalSent++
	}
}

// responseProcessorLoop traite les réponses reçues
func (d *DiskDownloader) responseProcessorLoop() {
	defer d.waitGroup.Done()

	for hash := range d.responseChannel {
		// Marquer comme reçu et ajuster la fenêtre
		d.pendingRequestsMu.Lock()
		if req, isPending := d.pendingRequests[hash]; isPending {
			if time.Since(req.sentAt) < d.requestTimeout/2 {
				// Réponse rapide → augmenter la fenêtre
				d.windowSize = utils.MinInt(d.windowSize+1, d.maxWindowSize)
			}
			delete(d.pendingRequests, hash)
			d.totalReceived++
		}
		d.pendingRequestsMu.Unlock()

		// Incrémenter le compteur de traitement
		d.activeProcessingMu.Lock()
		d.activeProcessing++
		d.activeProcessingMu.Unlock()

		// Traiter le datum
		d.datumCacheMu.RLock()
		datum, found := d.datumCache[hash]
		d.datumCacheMu.RUnlock()
		if found {
			d.processDatum(hash, datum)
		}

		// Décrémenter le compteur
		d.activeProcessingMu.Lock()
		d.activeProcessing--
		d.activeProcessingMu.Unlock()
	}
}

// timeoutMonitorLoop surveille les timeouts et relance les requêtes
func (d *DiskDownloader) timeoutMonitorLoop() {
	defer d.waitGroup.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for d.isRunning {
		<-ticker.C
		now := time.Now()
		var hashesToRetry [][32]byte

		d.pendingRequestsMu.Lock()
		for hash, req := range d.pendingRequests {
			if now.Sub(req.sentAt) > d.requestTimeout {
				if req.retryCount < 3 {
					req.retryCount++
					req.sentAt = now
					hashesToRetry = append(hashesToRetry, hash)
				} else {
					delete(d.pendingRequests, hash)
					d.totalTimeouts++
				}
			}
		}
		d.pendingRequestsMu.Unlock()

		// Relancer les requêtes et réduire la fenêtre (AIMD)
		for _, hash := range hashesToRetry {
			SendDatumRequest(d.server.Conn, d.peerAddress, hash)
			d.totalSent++
			d.windowSize = utils.MaxInt(d.windowSize/2, d.minWindowSize)
		}
	}
}

// processDatum traite un datum reçu selon son type
func (d *DiskDownloader) processDatum(hash [32]byte, datum []byte) {
	nodeType, nodeData := merkle.ParseDatum(datum)

	d.hashToPathMu.RLock()
	filePath := d.hashToPath[hash]
	d.hashToPathMu.RUnlock()

	switch nodeType {
	case merkle.TypeDirectory:
		d.processDirectory(filePath, nodeData)

	case merkle.TypeBigDirectory:
		d.processBigDirectory(filePath, nodeData)

	case merkle.TypeChunk:
		d.processChunk(hash, filePath, nodeData)

	case merkle.TypeBig:
		d.processBigFile(hash, filePath, nodeData)
	}
}

// processDirectory traite un répertoire
func (d *DiskDownloader) processDirectory(dirPath string, data []byte) {
	if dirPath != "" {
		os.MkdirAll(dirPath, 0755)
	}

	entries := merkle.ParseDirectoryEntries(data)
	for _, entry := range entries {
		childPath := ""
		if dirPath != "" {
			childPath = filepath.Join(dirPath, merkle.GetEntryName(entry))
		}
		d.QueueDownload(entry.Hash, childPath)
	}
}

// processBigDirectory traite un gros répertoire (>16 entrées)
func (d *DiskDownloader) processBigDirectory(dirPath string, data []byte) {
	childHashes := merkle.ParseBigHashes(data)
	for _, childHash := range childHashes {
		d.QueueDownload(childHash, dirPath)
	}
}

// processChunk traite un fichier simple (<= 1024 bytes)
func (d *DiskDownloader) processChunk(hash [32]byte, filePath string, data []byte) {
	if filePath != "" {
		if err := os.WriteFile(filePath, data, 0644); err == nil {
			d.filesSaved++
			d.bytesSaved += int64(len(data))
		}
	}
}

// processBigFile traite un gros fichier (> 1024 bytes, fragmenté)
func (d *DiskDownloader) processBigFile(hash [32]byte, filePath string, data []byte) {
	// Télécharger tous les morceaux
	childHashes := merkle.ParseBigHashes(data)
	for _, childHash := range childHashes {
		d.QueueDownload(childHash, "") // Pas de chemin pour les morceaux
	}

	// Marquer pour reconstruction ultérieure
	if filePath != "" {
		d.bigFilesToReconstructMu.Lock()
		d.bigFilesToReconstruct[hash] = filePath
		d.bigFilesToReconstructMu.Unlock()
	}
}

// reconstructBigFiles reconstruit tous les fichiers Big après téléchargement
func (d *DiskDownloader) reconstructBigFiles() {
	d.bigFilesToReconstructMu.Lock()
	filesToReconstruct := make(map[[32]byte]string)
	for hash, path := range d.bigFilesToReconstruct {
		filesToReconstruct[hash] = path
	}
	d.bigFilesToReconstructMu.Unlock()

	if len(filesToReconstruct) == 0 {
		return
	}

	fmt.Printf("🔨 Reconstruction de %d fichiers Big...\n", len(filesToReconstruct))
	for hash, filePath := range filesToReconstruct {
		content, err := d.reconstructBigFileContent(hash)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filePath, content, 0644); err == nil {
			d.filesSaved++
			d.bytesSaved += int64(len(content))
		}
	}
}

// reconstructBigFileContent reconstruit le contenu d'un fichier Big
func (d *DiskDownloader) reconstructBigFileContent(hash [32]byte) ([]byte, error) {
	d.datumCacheMu.RLock()
	datum, found := d.datumCache[hash]
	d.datumCacheMu.RUnlock()
	if !found {
		return nil, fmt.Errorf("datum non trouvé: %x", hash[:8])
	}

	nodeType, nodeData := merkle.ParseDatum(datum)
	switch nodeType {
	case merkle.TypeChunk:
		return nodeData, nil

	case merkle.TypeBig:
		var content []byte
		for _, childHash := range merkle.ParseBigHashes(nodeData) {
			childContent, err := d.reconstructBigFileContent(childHash)
			if err != nil {
				return nil, err
			}
			content = append(content, childContent...)
		}
		return content, nil
	}
	return nil, fmt.Errorf("type de datum non supporté: %d", nodeType)
}

// displayProgress affiche la progression du téléchargement
func (d *DiskDownloader) displayProgress() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for d.isRunning {
		<-ticker.C

		d.datumCacheMu.RLock()
		cachedCount := len(d.datumCache)
		d.datumCacheMu.RUnlock()

		d.pendingRequestsMu.Lock()
		pendingCount := len(d.pendingRequests)
		d.pendingRequestsMu.Unlock()

		fmt.Printf("\r📊 Datums: %d | Fichiers: %d | En attente: %d   ",
			cachedCount, d.filesSaved, pendingCount)
	}
}
