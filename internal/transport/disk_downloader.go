package transport

import (
	"fmt"
	"main/internal/merkle"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DiskDownloader télécharge directement sur disque avec fenêtre glissante
type DiskDownloader struct {
	server   *Server
	peerAddr *net.UDPAddr
	baseDir  string

	// Fenêtre glissante
	windowSize    int
	maxWindowSize int
	minWindowSize int
	timeout       time.Duration

	// Requêtes en cours
	pending    map[[32]byte]*pendingReq
	pendingMu  sync.Mutex
	responseCh chan [32]byte

	// Cache des datums et mapping des chemins
	cache     map[[32]byte][]byte
	cacheMu   sync.RWMutex
	pathMap   map[[32]byte]string
	pathMapMu sync.RWMutex

	// Fichiers Big à reconstruire
	bigFiles   map[[32]byte]string
	bigFilesMu sync.Mutex

	// Traitement en cours
	processing   int
	processingMu sync.Mutex

	// Stats
	sent, received, timeouts int
	filesaved                int
	bytesTotal               int64

	// File d'attente
	queue     []task
	queueMu   sync.Mutex
	queueCond *sync.Cond

	running bool
	wg      sync.WaitGroup
}

type pendingReq struct {
	hash    [32]byte
	sentAt  time.Time
	retries int
}

type task struct {
	hash [32]byte
	path string
}

// NewDiskDownloader crée un nouveau downloader
func NewDiskDownloader(server *Server, peerAddr *net.UDPAddr, baseDir string) *DiskDownloader {
	d := &DiskDownloader{
		server:        server,
		peerAddr:      peerAddr,
		baseDir:       baseDir,
		windowSize:    8,
		maxWindowSize: 64,
		minWindowSize: 1,
		timeout:       2 * time.Second,
		pending:       make(map[[32]byte]*pendingReq),
		responseCh:    make(chan [32]byte, 200),
		cache:         make(map[[32]byte][]byte),
		pathMap:       make(map[[32]byte]string),
		bigFiles:      make(map[[32]byte]string),
		queue:         make([]task, 0),
		running:       true,
	}
	d.queueCond = sync.NewCond(&d.queueMu)
	return d
}

func (d *DiskDownloader) Start() {
	d.wg.Add(3)
	go d.sender()
	go d.responseWatcher()
	go d.timeoutWatcher()
}

func (d *DiskDownloader) Stop() {
	d.running = false
	d.queueCond.Broadcast()
	close(d.responseCh)
	d.wg.Wait()
}

// QueueDownload ajoute un hash à télécharger
func (d *DiskDownloader) QueueDownload(hash [32]byte, path string) {
	if path != "" {
		d.pathMapMu.Lock()
		d.pathMap[hash] = path
		d.pathMapMu.Unlock()
	}

	d.cacheMu.RLock()
	_, inCache := d.cache[hash]
	d.cacheMu.RUnlock()
	if inCache {
		return
	}

	d.queueMu.Lock()
	d.queue = append(d.queue, task{hash: hash, path: path})
	d.queueMu.Unlock()
	d.queueCond.Signal()
}

// NotifyReceived est appelé quand un datum est reçu
func (d *DiskDownloader) NotifyReceived(hash [32]byte, datum []byte) {
	d.cacheMu.Lock()
	d.cache[hash] = datum
	d.cacheMu.Unlock()

	select {
	case d.responseCh <- hash:
	case <-time.After(1 * time.Second):
	}
}

// WaitComplete attend la fin des téléchargements
func (d *DiskDownloader) WaitComplete() {
	for {
		d.queueMu.Lock()
		qLen := len(d.queue)
		d.queueMu.Unlock()

		d.pendingMu.Lock()
		pLen := len(d.pending)
		d.pendingMu.Unlock()

		d.processingMu.Lock()
		proc := d.processing
		d.processingMu.Unlock()

		if qLen == 0 && pLen == 0 && proc == 0 {
			time.Sleep(200 * time.Millisecond)
			// Double vérification
			d.queueMu.Lock()
			qLen = len(d.queue)
			d.queueMu.Unlock()
			d.pendingMu.Lock()
			pLen = len(d.pending)
			d.pendingMu.Unlock()
			d.processingMu.Lock()
			proc = d.processing
			d.processingMu.Unlock()
			if qLen == 0 && pLen == 0 && proc == 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (d *DiskDownloader) sender() {
	defer d.wg.Done()
	for d.running {
		d.pendingMu.Lock()
		if len(d.pending) >= d.windowSize {
			d.pendingMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		d.pendingMu.Unlock()

		d.queueMu.Lock()
		for len(d.queue) == 0 && d.running {
			d.queueCond.Wait()
		}
		if !d.running {
			d.queueMu.Unlock()
			return
		}
		t := d.queue[0]
		d.queue = d.queue[1:]
		d.queueMu.Unlock()

		d.cacheMu.RLock()
		_, inCache := d.cache[t.hash]
		d.cacheMu.RUnlock()
		if inCache {
			continue
		}

		d.pendingMu.Lock()
		if _, ok := d.pending[t.hash]; ok {
			d.pendingMu.Unlock()
			continue
		}
		d.pending[t.hash] = &pendingReq{hash: t.hash, sentAt: time.Now()}
		d.pendingMu.Unlock()

		SendDatumRequest(d.server.Conn, d.peerAddr, t.hash)
		d.sent++
	}
}

func (d *DiskDownloader) responseWatcher() {
	defer d.wg.Done()
	for hash := range d.responseCh {
		d.pendingMu.Lock()
		if req, ok := d.pending[hash]; ok {
			if time.Since(req.sentAt) < d.timeout/2 {
				d.windowSize = minInt(d.windowSize+1, d.maxWindowSize)
			}
			delete(d.pending, hash)
			d.received++
		}
		d.pendingMu.Unlock()

		d.processingMu.Lock()
		d.processing++
		d.processingMu.Unlock()

		d.cacheMu.RLock()
		datum, ok := d.cache[hash]
		d.cacheMu.RUnlock()
		if ok {
			d.processDatum(hash, datum)
		}

		d.processingMu.Lock()
		d.processing--
		d.processingMu.Unlock()
	}
}

func (d *DiskDownloader) processDatum(hash [32]byte, datum []byte) {
	nodeType, data := merkle.ParseDatum(datum)

	d.pathMapMu.RLock()
	path := d.pathMap[hash]
	d.pathMapMu.RUnlock()

	switch nodeType {
	case merkle.TypeDirectory:
		if path != "" {
			os.MkdirAll(path, 0755)
		}
		entries := merkle.ParseDirectoryEntries(data)
		for _, entry := range entries {
			childPath := ""
			if path != "" {
				childPath = filepath.Join(path, merkle.GetEntryName(entry))
			}
			d.QueueDownload(entry.Hash, childPath)
		}

	case merkle.TypeBigDirectory:
		for _, h := range merkle.ParseBigHashes(data) {
			d.QueueDownload(h, path)
		}

	case merkle.TypeChunk:
		if path != "" {
			if err := os.WriteFile(path, data, 0644); err == nil {
				d.filesaved++
				d.bytesTotal += int64(len(data))
			}
		}

	case merkle.TypeBig:
		for _, h := range merkle.ParseBigHashes(data) {
			d.QueueDownload(h, "")
		}
		if path != "" {
			d.bigFilesMu.Lock()
			d.bigFiles[hash] = path
			d.bigFilesMu.Unlock()
		}
	}
}

func (d *DiskDownloader) timeoutWatcher() {
	defer d.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for d.running {
		<-ticker.C
		now := time.Now()
		var toRetry [][32]byte

		d.pendingMu.Lock()
		for hash, req := range d.pending {
			if now.Sub(req.sentAt) > d.timeout {
				if req.retries < 3 {
					req.retries++
					req.sentAt = now
					toRetry = append(toRetry, hash)
				} else {
					delete(d.pending, hash)
					d.timeouts++
				}
			}
		}
		d.pendingMu.Unlock()

		for _, hash := range toRetry {
			SendDatumRequest(d.server.Conn, d.peerAddr, hash)
			d.sent++
			d.windowSize = maxInt(d.windowSize/2, d.minWindowSize)
		}
	}
}

func (d *DiskDownloader) reconstructAllBigFiles() {
	d.bigFilesMu.Lock()
	bigFiles := make(map[[32]byte]string)
	for h, p := range d.bigFiles {
		bigFiles[h] = p
	}
	d.bigFilesMu.Unlock()

	if len(bigFiles) == 0 {
		return
	}

	fmt.Printf("🔨 Reconstruction de %d fichiers Big...\n", len(bigFiles))
	for hash, path := range bigFiles {
		if content, err := d.reconstructBig(hash); err == nil {
			if err := os.WriteFile(path, content, 0644); err == nil {
				d.filesaved++
				d.bytesTotal += int64(len(content))
			}
		}
	}
}

func (d *DiskDownloader) reconstructBig(hash [32]byte) ([]byte, error) {
	d.cacheMu.RLock()
	datum, ok := d.cache[hash]
	d.cacheMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("hash non trouvé")
	}

	nodeType, data := merkle.ParseDatum(datum)
	switch nodeType {
	case merkle.TypeChunk:
		return data, nil
	case merkle.TypeBig:
		var content []byte
		for _, h := range merkle.ParseBigHashes(data) {
			child, err := d.reconstructBig(h)
			if err != nil {
				return nil, err
			}
			content = append(content, child...)
		}
		return content, nil
	}
	return nil, fmt.Errorf("type non supporté")
}

// DownloadToDisk télécharge et sauvegarde sur disque
func (d *DiskDownloader) DownloadToDisk(rootHash [32]byte) error {
	if err := os.MkdirAll(d.baseDir, 0755); err != nil {
		return err
	}

	fmt.Printf("📥 Téléchargement vers %s\n", d.baseDir)
	d.Start()
	d.QueueDownload(rootHash, d.baseDir)

	// Progression
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for d.running {
			<-ticker.C
			d.cacheMu.RLock()
			cached := len(d.cache)
			d.cacheMu.RUnlock()
			d.pendingMu.Lock()
			pending := len(d.pending)
			d.pendingMu.Unlock()
			fmt.Printf("\r📊 Datums: %d | Fichiers: %d | En attente: %d   ", cached, d.filesaved, pending)
		}
	}()

	d.WaitComplete()
	d.reconstructAllBigFiles()
	d.Stop()

	fmt.Printf("\n✅ Terminé: %d fichiers, %s\n", d.filesaved, formatBytes(d.bytesTotal))
	if d.timeouts > 0 {
		fmt.Printf("⚠️  %d timeout(s)\n", d.timeouts)
	}
	return nil
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
