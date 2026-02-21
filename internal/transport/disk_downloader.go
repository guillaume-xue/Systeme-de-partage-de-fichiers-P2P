package transport

import (
	"context"
	"fmt"
	"io"
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
type DiskDownloader struct {
	server    *Server
	peer      *net.UDPAddr
	outputDir string
	tempDir   string // dossier pour les chunks temporaires
	tracker   *InflightTracker

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
	savedFiles int
	savedBytes int64
	statsMu    sync.Mutex

	// Lifecycle
	wg          sync.WaitGroup
	unsubscribe func()
	running     bool
	done        chan struct{}

	// Nom réel de la racine (extrait du répertoire parent)
	rootName string

	// Semaphore pour limiter les goroutines de processing
	processorSem    chan struct{}
	processingCount int
	processingMu    sync.Mutex
}

func NewDiskDownloader(server *Server, peer *net.UDPAddr, output string) *DiskDownloader {
	tempDir := filepath.Join(output, ".tmp_chunks")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		fmt.Printf("⚠️ Impossible de créer le dossier temporaire: %v\n", err)
	}

	cfg := config.GlobalConfig.Network
	fc := NewFlowControl(cfg.InitialWindow, cfg.MinWindowSize, cfg.MaxWindowSize, cfg.TimeoutDownload)
	return &DiskDownloader{
		server:    server,
		peer:      peer,
		outputDir: output,
		tempDir:   tempDir,
		tracker:   NewInflightTracker(fc, server.Pending, peer),

		workQueue:  make(chan task, config.GlobalConfig.Network.MaxQueueSize),
		responseCh: make(chan [32]byte, config.GlobalConfig.Network.MaxQueueSize),

		pathMap:        make(map[[32]byte]string),
		bigFiles:       make(map[[32]byte]string),
		structureCache: make(map[[32]byte][]byte),

		running:      true,
		done:         make(chan struct{}),
		processorSem: make(chan struct{}, config.GlobalConfig.Network.ProcessorWorkers),
	}
}

// DownloadToDisk télécharge l'arborescence complète et la sauvegarde sur disque.
// rootName est le nom réel du fichier/dossier racine (extrait du parent). Si vide, un nom basé sur le hash est utilisé.
func (d *DiskDownloader) DownloadToDisk(ctx context.Context, rootHash [32]byte, rootName string) error {
	d.rootName = rootName
	if err := os.MkdirAll(d.outputDir, 0755); err != nil {
		return fmt.Errorf("mkdir fail: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	d.unsubscribe = d.server.DatumDispatcher.Subscribe(d.onDatumReceived)

	fmt.Printf("ℹ️️ Start DL -> %s (Root: %x...)\n", d.outputDir, rootHash)

	d.wg.Add(3)
	go d.senderLoop()
	go d.processorLoop()
	go d.monitorLoop()

	d.workQueue <- task{hash: rootHash, path: "__ROOT__"}

	select {
	case <-d.done:
	case <-ctx.Done():
		d.stop()
		os.RemoveAll(d.tempDir)
		return ctx.Err()
	}

	d.finalizeBigFiles()
	d.stop()
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

	d.tracker.CleanupAll()
}

// Callback UDP
func (d *DiskDownloader) onDatumReceived(hash [32]byte, data []byte) {
	d.tracker.OnReceived(hash)

	// Stockage selon le type : chunks sur disque, structure en RAM
	typ, _ := merkle.ParseDatum(data)

	if typ == merkle.TypeChunk {
		if err := d.writeTempChunk(hash, data); err != nil {
			fmt.Printf("❌ Erreur écriture temp chunk %x: %v\n", hash, err)
			return
		}
	} else {
		d.structureCacheMu.Lock()
		d.structureCache[hash] = data
		d.structureCacheMu.Unlock()
	}

	// Signal garanti via goroutine
	go func() {
		select {
		case d.responseCh <- hash:
		case <-d.done:
		}
	}()
}

// writeTempChunk écrit un chunk sur le disque dans le dossier temp
func (d *DiskDownloader) writeTempChunk(hash [32]byte, data []byte) error {
	return os.WriteFile(d.getTempChunkPath(hash), data, 0644)
}

// WORKER 1 : Envoie les requêtes
func (d *DiskDownloader) senderLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(time.Duration(config.GlobalConfig.Network.DiskSenderTickMs) * time.Millisecond)
	defer ticker.Stop()

	for d.running {
		if !d.tracker.CanSend() {
			select {
			case <-ticker.C:
				continue
			case <-d.done:
				return
			}
		}

		select {
		case tache, ok := <-d.workQueue:
			if !ok {
				return
			}

			if d.hasDatum(tache.hash) {
				d.processDatum(tache.hash, tache.path)
				continue
			}

			if d.tracker.IsTracked(tache.hash) {
				continue
			}

			d.trackPath(tache.hash, tache.path)
			d.tracker.Track(tache.hash)
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

func (d *DiskDownloader) getTempChunkPath(hash [32]byte) string {
	return filepath.Join(d.tempDir, fmt.Sprintf("%x", hash))
}

// readDatum lit un datum depuis la RAM (structure) ou le disque (chunk)
func (d *DiskDownloader) readDatum(hash [32]byte) ([]byte, bool) {
	d.structureCacheMu.RLock()
	data, inRam := d.structureCache[hash]
	d.structureCacheMu.RUnlock()
	if inRam {
		return data, true
	}

	data, err := os.ReadFile(d.getTempChunkPath(hash))
	if err != nil {
		return nil, false
	}
	return data, true
}

// hasDatum vérifie si un datum existe en RAM ou sur disque
func (d *DiskDownloader) hasDatum(hash [32]byte) bool {
	d.structureCacheMu.RLock()
	_, inRam := d.structureCache[hash]
	d.structureCacheMu.RUnlock()
	if inRam {
		return true
	}
	return d.hasTempChunk(hash)
}

func (d *DiskDownloader) recordSuccess(size int64) {
	d.statsMu.Lock()
	d.savedFiles++
	d.savedBytes += size
	d.statsMu.Unlock()
}

// getCompletionStatus retourne les compteurs pour la détection de fin
func (d *DiskDownloader) getCompletionStatus() (inflight, queued, response, processing int) {
	inflight = d.tracker.Count()
	queued = len(d.workQueue)
	response = len(d.responseCh)

	d.processingMu.Lock()
	processing = d.processingCount
	d.processingMu.Unlock()
	return
}

func (d *DiskDownloader) isDownloadComplete() bool {
	inflight, queued, response, processing := d.getCompletionStatus()
	return inflight == 0 && queued == 0 && response == 0 && processing == 0
}

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
		d.processorSem <- struct{}{}

		d.processingMu.Lock()
		d.processingCount++
		d.processingMu.Unlock()

		go func(h [32]byte) {
			defer func() {
				<-d.processorSem
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
	tick := time.NewTicker(time.Duration(config.GlobalConfig.Network.DiskMonitorIntervalMs) * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		inflight, queued, response, processing := d.getCompletionStatus()
		windowSize, rtt, rto := d.tracker.Snapshot()

		savedFiles, savedBytes := d.getStats()

		fmt.Printf("\r%-100s\r", "")
		fmt.Printf("ℹ️️ DL: (%d fichiers, %s) | Vol: %d | File: %d | Fen: %d | RTT: %s | RTO: %s",
			savedFiles, utils.FormatBytesInt64(savedBytes), inflight, queued, windowSize,
			rtt.Round(time.Millisecond), rto.Round(time.Millisecond))

		// Logique de fin
		if inflight == 0 && queued == 0 && response == 0 && processing == 0 {
			time.Sleep(time.Duration(config.GlobalConfig.Network.DiskCompletionConfirmDelayMs) * time.Millisecond)
			if d.isDownloadComplete() {
				fmt.Println()
				close(d.done)
				return
			}
		}

		// Gestion des timeouts et retransmission via le tracker
		retryList := d.tracker.HandleTimeouts()
		d.tracker.RetransmitAll(d.server.Conn, retryList, d.hasDatum)
	}
}

// Traitement d'un datum reçu
func (d *DiskDownloader) processDatum(hash [32]byte, destPath string) {
	data, found := d.readDatum(hash)
	if !found {
		return
	}

	typ, content := merkle.ParseDatum(data)

	if destPath == "__ROOT__" {
		name := d.rootName
		if name == "" {
			if typ == merkle.TypeDirectory || typ == merkle.TypeBigDirectory {
				name = fmt.Sprintf("dir_%x", hash)
			} else {
				name = fmt.Sprintf("file_%x", hash)
			}
		}
		destPath = filepath.Join(d.outputDir, name)
		fmt.Printf("ℹ️️ Type détecté: %d, destination: %s\n", typ, destPath)
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
			select {
			case d.workQueue <- task{hash: e.Hash, path: childPath}:
			case <-d.done:
				return
			}
		}

	case merkle.TypeBigDirectory:
		hashes := merkle.ParseBigHashes(content)
		for _, hash := range hashes {
			select {
			case d.workQueue <- task{hash: hash, path: destPath}:
			case <-d.done:
				return
			}
		}

	case merkle.TypeChunk:
		if destPath != "" {
			err := os.WriteFile(destPath, content, 0644)
			if err == nil {
				d.recordSuccess(int64(len(content)))
			}
		}

	case merkle.TypeBig:
		if destPath != "" {
			d.bigFilesMu.Lock()
			d.bigFiles[hash] = destPath
			d.bigFilesMu.Unlock()
		}
		hashes := merkle.ParseBigHashes(content)
		for _, h := range hashes {
			select {
			case d.workQueue <- task{hash: h, path: ""}:
			case <-d.done:
				return
			}
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

	fmt.Printf("\nℹ️️ Reconstruction de %d gros fichiers...\n", len(d.bigFiles))

	for hash, path := range d.bigFiles {
		fmt.Printf("ℹ️️ Assemblage %s... ", filepath.Base(path))

		outFile, err := os.Create(path)
		if err != nil {
			fmt.Printf("❌ Erreur création: %v\n", err)
			continue
		}

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
func (d *DiskDownloader) assembleStream(hash [32]byte, writer io.Writer) (int64, error) {
	d.structureCacheMu.RLock()
	data, isStruct := d.structureCache[hash]
	d.structureCacheMu.RUnlock()

	if isStruct {
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

	chunkPath := d.getTempChunkPath(hash)
	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		return 0, fmt.Errorf("chunk manquant: %x", hash)
	}

	defer os.Remove(chunkPath)

	_, content := merkle.ParseDatum(chunkData)

	n, err := writer.Write(content)
	return int64(n), err
}
