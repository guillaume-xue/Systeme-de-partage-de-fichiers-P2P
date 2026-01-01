package transport

import (
	"fmt"
	"main/internal/merkle"
	"net"
	"sync"
	"time"
)

// Downloader gère les téléchargements avec fenêtre glissante et contrôle de congestion
type Downloader struct {
	server   *Server
	peerAddr *net.UDPAddr

	// Fenêtre glissante
	windowSize    int           // Taille actuelle de la fenêtre
	maxWindowSize int           // Taille max de la fenêtre
	minWindowSize int           // Taille min de la fenêtre
	timeout       time.Duration // Timeout pour les requêtes

	// Requêtes en cours
	pending    map[[32]byte]*pendingRequest
	pendingMu  sync.Mutex
	responseCh chan [32]byte // Canal pour signaler les réponses reçues

	// Statistiques
	sent      int
	received  int
	timeouts  int
	duplicate int

	// File d'attente des hash à télécharger
	queue     [][32]byte
	queueMu   sync.Mutex
	queueCond *sync.Cond

	// Contrôle
	running bool
	wg      sync.WaitGroup
}

type pendingRequest struct {
	hash     [32]byte
	sentAt   time.Time
	retries  int
	maxRetry int
}

// NewDownloader crée un nouveau gestionnaire de téléchargement
func NewDownloader(server *Server, peerAddr *net.UDPAddr) *Downloader {
	d := &Downloader{
		server:        server,
		peerAddr:      peerAddr,
		windowSize:    4,  // Fenêtre initiale
		maxWindowSize: 32, // Max 32 requêtes en parallèle
		minWindowSize: 1,  // Min 1 requête
		timeout:       2 * time.Second,
		pending:       make(map[[32]byte]*pendingRequest),
		responseCh:    make(chan [32]byte, 100),
		queue:         make([][32]byte, 0),
		running:       true,
	}
	d.queueCond = sync.NewCond(&d.queueMu)
	return d
}

// Start démarre le downloader
func (d *Downloader) Start() {
	// Goroutine pour surveiller les réponses
	d.wg.Add(1)
	go d.responseWatcher()

	// Goroutine pour le timeout et retransmission
	d.wg.Add(1)
	go d.timeoutWatcher()

	// Goroutine pour envoyer les requêtes
	d.wg.Add(1)
	go d.sender()
}

// Stop arrête le downloader
func (d *Downloader) Stop() {
	d.running = false
	d.queueCond.Broadcast()
	close(d.responseCh)
	d.wg.Wait()
}

// QueueHash ajoute un hash à la file d'attente
func (d *Downloader) QueueHash(hash [32]byte) {
	// Vérifier si on l'a déjà
	if _, ok := d.server.Downloads.Get(hash); ok {
		return
	}

	d.queueMu.Lock()
	d.queue = append(d.queue, hash)
	d.queueMu.Unlock()
	d.queueCond.Signal()
}

// QueueHashes ajoute plusieurs hash à la file d'attente
func (d *Downloader) QueueHashes(hashes [][32]byte) {
	d.queueMu.Lock()
	for _, hash := range hashes {
		// Vérifier si on l'a déjà
		if _, ok := d.server.Downloads.Get(hash); !ok {
			d.queue = append(d.queue, hash)
		}
	}
	d.queueMu.Unlock()
	d.queueCond.Broadcast()
}

// NotifyReceived est appelé quand un datum est reçu
func (d *Downloader) NotifyReceived(hash [32]byte, _ []byte) {
	select {
	case d.responseCh <- hash:
	default:
		// Canal plein, ignorer
	}
}

// WaitComplete attend que tous les téléchargements soient terminés
func (d *Downloader) WaitComplete() {
	for {
		d.queueMu.Lock()
		queueEmpty := len(d.queue) == 0
		d.queueMu.Unlock()

		d.pendingMu.Lock()
		pendingEmpty := len(d.pending) == 0
		d.pendingMu.Unlock()

		if queueEmpty && pendingEmpty {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// GetStats retourne les statistiques
func (d *Downloader) GetStats() (sent, received, timeouts, duplicate int) {
	return d.sent, d.received, d.timeouts, d.duplicate
}

// sender envoie les requêtes depuis la queue
func (d *Downloader) sender() {
	defer d.wg.Done()

	for d.running {
		// Attendre qu'il y ait de la place dans la fenêtre et des hash à envoyer
		d.pendingMu.Lock()
		currentPending := len(d.pending)
		d.pendingMu.Unlock()

		if currentPending >= d.windowSize {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Prendre un hash de la queue
		d.queueMu.Lock()
		for len(d.queue) == 0 && d.running {
			d.queueCond.Wait()
		}
		if !d.running {
			d.queueMu.Unlock()
			return
		}

		hash := d.queue[0]
		d.queue = d.queue[1:]
		d.queueMu.Unlock()

		// Vérifier si on l'a déjà
		if _, ok := d.server.Downloads.Get(hash); ok {
			d.duplicate++
			continue
		}

		// Vérifier si déjà en attente
		d.pendingMu.Lock()
		if _, ok := d.pending[hash]; ok {
			d.pendingMu.Unlock()
			continue
		}

		// Ajouter aux requêtes en attente
		d.pending[hash] = &pendingRequest{
			hash:     hash,
			sentAt:   time.Now(),
			retries:  0,
			maxRetry: 3,
		}
		d.pendingMu.Unlock()

		// Envoyer la requête
		SendDatumRequest(d.server.Conn, d.peerAddr, hash)
		d.sent++
	}
}

// responseWatcher surveille les réponses
func (d *Downloader) responseWatcher() {
	defer d.wg.Done()

	for hash := range d.responseCh {
		d.pendingMu.Lock()
		req, ok := d.pending[hash]
		if ok {
			// Calculer le RTT pour ajuster le timeout
			rtt := time.Since(req.sentAt)
			if rtt < d.timeout/2 {
				// Réponse rapide, augmenter la fenêtre
				d.increaseWindow()
			}

			delete(d.pending, hash)
			d.received++
		}
		d.pendingMu.Unlock()

		// Traiter le datum reçu pour ajouter les enfants à la queue
		if datum, ok := d.server.Downloads.Get(hash); ok {
			d.processChildren(datum)
		}
	}
}

// timeoutWatcher gère les timeouts et retransmissions
func (d *Downloader) timeoutWatcher() {
	defer d.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for d.running {
		<-ticker.C

		now := time.Now()
		var toRetry [][32]byte
		var toRemove [][32]byte

		d.pendingMu.Lock()
		for hash, req := range d.pending {
			if now.Sub(req.sentAt) > d.timeout {
				if req.retries < req.maxRetry {
					req.retries++
					req.sentAt = now
					toRetry = append(toRetry, hash)
				} else {
					toRemove = append(toRemove, hash)
					d.timeouts++
				}
			}
		}

		// Supprimer les requêtes qui ont trop de retries
		for _, hash := range toRemove {
			delete(d.pending, hash)
		}
		d.pendingMu.Unlock()

		// Retransmettre
		for _, hash := range toRetry {
			SendDatumRequest(d.server.Conn, d.peerAddr, hash)
			d.sent++
			// Réduire la fenêtre (congestion)
			d.decreaseWindow()
		}
	}
}

// processChildren ajoute les hash enfants à la queue
func (d *Downloader) processChildren(datum []byte) {
	nodeType, data := merkle.ParseDatum(datum)

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(data)
		hashes := make([][32]byte, len(entries))
		for i, entry := range entries {
			hashes[i] = entry.Hash
		}
		d.QueueHashes(hashes)

	case merkle.TypeBig, merkle.TypeBigDirectory:
		hashes := merkle.ParseBigHashes(data)
		d.QueueHashes(hashes)
	}
}

// increaseWindow augmente la taille de la fenêtre (additive increase)
func (d *Downloader) increaseWindow() {
	if d.windowSize < d.maxWindowSize {
		d.windowSize++
	}
}

// decreaseWindow réduit la taille de la fenêtre (multiplicative decrease)
func (d *Downloader) decreaseWindow() {
	d.windowSize = max(d.windowSize / 2, d.minWindowSize)
}

// DownloadTree télécharge récursivement un arbre Merkle
func (d *Downloader) DownloadTree(rootHash [32]byte) {
	fmt.Printf("🚀 Démarrage du téléchargement (fenêtre: %d)\n", d.windowSize)

	d.Start()
	d.QueueHash(rootHash)

	// Afficher la progression
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for d.running {
			<-ticker.C
			d.pendingMu.Lock()
			pending := len(d.pending)
			d.pendingMu.Unlock()

			d.queueMu.Lock()
			queued := len(d.queue)
			d.queueMu.Unlock()

			downloaded := d.server.Downloads.Len()
			fmt.Printf("\r📊 Téléchargés: %d | En attente: %d | Queue: %d | Fenêtre: %d   ",
				downloaded, pending, queued, d.windowSize)
		}
	}()

	d.WaitComplete()
	d.Stop()

	fmt.Printf("\n✅ Téléchargement terminé!\n")
	sent, received, timeouts, dup := d.GetStats()
	fmt.Printf("   📈 Stats: %d envoyés, %d reçus, %d timeouts, %d duplicates\n",
		sent, received, timeouts, dup)
}
