package transport

import (
	"fmt"
	"main/internal/config"
	"main/internal/merkle"
	"main/internal/protocol"
	"main/internal/utils"
	"net"
	"sync"
	"time"
)

// Downloader : Gère le téléchargement "en mémoire" (pour explorer l'arbre)
// Contrairement au DiskDownloader, on ne stocke pas les fichiers sur le disque,
// on remplit juste le store "server.Downloads".
type Downloader struct {
	server   *Server
	peerAddr *net.UDPAddr

	// Gestion de fenêtre
	windowSize    int
	maxWindowSize int
	minWindowSize int
	timeout       time.Duration

	// État des requêtes
	pending map[[32]byte]time.Time // Hash -> Heure d'envoi
	retries map[[32]byte]int
	mu      sync.Mutex

	// Stats de progression
	totalReceived int
	statsMu       sync.Mutex

	// RTT estimation (RFC 6298) + contrôle de congestion
	srtt     time.Duration // Moyenne lissée du RTT
	rttvar   time.Duration // Variance lissée du RTT
	rto      time.Duration // Timeout de retransmission dynamique
	rttInit  bool          // Premier échantillon RTT reçu ?
	ssthresh int           // Seuil slow-start / congestion avoidance

	// Communication interne
	workCh     chan [32]byte // File d'attente des hash à demander
	responseCh chan [32]byte // Signal de réception

	// Buffer de débordement pour ne jamais perdre de hash
	overflowMu sync.Mutex
	overflow   [][32]byte

	done chan struct{}

	// Contrôle
	running     bool
	wg          sync.WaitGroup
	unsubscribe func() // Closure de nettoyage du dispatcher
}

func NewDownloader(server *Server, peerAddr *net.UDPAddr) *Downloader {
	return &Downloader{
		server:   server,
		peerAddr: peerAddr,

		windowSize:    config.GlobalConfig.Network.InitialWindow,
		maxWindowSize: config.GlobalConfig.Network.MaxWindowSize,
		minWindowSize: config.GlobalConfig.Network.MinWindowSize,
		timeout:       config.GlobalConfig.Network.TimeoutDownload,

		// RTT init
		rto:      config.GlobalConfig.Network.TimeoutDownload, // RTO initial = timeout config
		ssthresh: config.GlobalConfig.Network.MaxWindowSize,   // Slow-start jusqu'à maxWindow

		pending: make(map[[32]byte]time.Time),
		retries: make(map[[32]byte]int),

		// Buffer large pour ne pas bloquer l'exploration récursive
		workCh:     make(chan [32]byte, protocol.MaxQueueSize),
		responseCh: make(chan [32]byte, protocol.MaxQueueSize),

		done:    make(chan struct{}),
		running: true,
	}
}

// Start lance les workers
func (d *Downloader) Start() {
	// On s'abonne avec un nom bidon pour le debug
	d.unsubscribe = d.server.DatumDispatcher.Subscribe("tree_walker", d.onDatumReceived)

	d.wg.Add(3)
	go d.senderLoop()
	go d.responseLoop()
	go d.monitorLoop()
}

// Stop nettoie tout
func (d *Downloader) Stop() {
	d.running = false

	if d.unsubscribe != nil {
		d.unsubscribe()
	}

	// On ferme les channels pour arrêter les workers proprement
	close(d.workCh)
	close(d.responseCh)

	d.wg.Wait()
}

// DownloadTree est la méthode bloquante appelée par le Menu
func (d *Downloader) DownloadTree(rootHash [32]byte) {
	fmt.Printf("🌳 Exploration de l'arbre %x...\n", rootHash)

	d.Start()

	// On injecte la racine
	d.workCh <- rootHash
	<-d.done // On attend la fin

	d.Stop()
	fmt.Println("\n✅ Exploration terminée.")
}

// Callback du dispatcher — retrait immédiat de pending pour éviter les faux timeouts
func (d *Downloader) onDatumReceived(hash [32]byte, _ []byte) {
	// Retirer de pending DÈS la réception UDP (pas dans responseLoop)
	// Sinon sur un PC lent, le traitement des enfants bloque responseLoop
	// et le monitor croit que ces paquets n'ont pas été reçus → faux timeout
	d.mu.Lock()
	sentAt, ok := d.pending[hash]
	wasRetried := d.retries[hash] > 0 // Karn
	if ok {
		responseTime := time.Since(sentAt)
		if !wasRetried {
			d.updateRTTAndWindow(responseTime)
		} else {
			d.growWindowOnly(responseTime)
		}
		d.removeFromPendingDownloader(hash)
	}
	d.mu.Unlock()

	// Signal garanti : goroutine pour ne pas bloquer le callback UDP
	// et ne jamais perdre de signal (sinon enfants jamais explorés)
	go func() { d.responseCh <- hash }()
}

// Worker 1 : Envoie les demandes
func (d *Downloader) senderLoop() {
	defer d.wg.Done()

	for d.running {
		// 0. Vider le buffer de débordement si possible
		d.drainOverflow()

		// 1. Check Window
		d.mu.Lock()
		canSend := len(d.pending) < d.windowSize
		d.mu.Unlock()

		if !canSend {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// 2. Get Job
		hash, ok := <-d.workCh
		if !ok {
			return
		}

		// 3. Check si on l'a déjà
		if _, exists := d.server.Downloads.Get(hash); exists {
			// On relance l'analyse des enfants pour être sûr d'avoir tout l'arbre.
			datum, _ := d.server.Downloads.Get(hash)
			d.processChildren(datum)
			continue
		}

		// 4. Check si déjà en cours
		d.mu.Lock()
		if _, inflight := d.pending[hash]; inflight {
			d.mu.Unlock()
			continue
		}

		d.pending[hash] = time.Now()
		d.mu.Unlock()

		// 5. Send (enregistrer d'abord pour la sécurité)
		d.server.RegisterDatumRequest(hash, d.peerAddr)
		SendDatumRequest(d.server.Conn, d.peerAddr, hash)
	}
}

// Worker 2 : Traite les réceptions (exploration des enfants uniquement)
func (d *Downloader) responseLoop() {
	defer d.wg.Done()

	for hash := range d.responseCh {
		d.statsMu.Lock()
		d.totalReceived++
		d.statsMu.Unlock()

		// Exploration des enfants (partie lente, découplée du timing réseau)
		if datum, ok := d.server.Downloads.Get(hash); ok {
			d.processChildren(datum)
		}
	}
}

// Worker 3 : Monitor (Timeouts + Détection de fin)
func (d *Downloader) monitorLoop() {
	defer d.wg.Done()

	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		d.mu.Lock()
		inflightCount := len(d.pending)
		windowSize := d.windowSize
		rtt := d.srtt
		rto := d.rto

		queuedCount := len(d.workCh)

		d.statsMu.Lock()
		received := d.totalReceived
		d.statsMu.Unlock()

		fmt.Printf("\r%-100s\r", "") // Nettoyer avec 100 espaces
		fmt.Printf("📊 %d reçus | Vol: %d | File: %d | Fen: %d | RTT: %s | RTO: %s",
			received, inflightCount, queuedCount, windowSize,
			rtt.Round(time.Millisecond), rto.Round(time.Millisecond))

		// Si plus rien en vol et plus rien à faire...
		d.overflowMu.Lock()
		overflowCount := len(d.overflow)
		d.overflowMu.Unlock()

		if inflightCount == 0 && queuedCount == 0 && overflowCount == 0 {
			// Petite sécurité : on lâche le lock, on attend un poil et on revérifie
			// (Au cas où un packet est en cours de traitement dans responseLoop)
			d.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			d.mu.Lock()

			d.overflowMu.Lock()
			overflowCount = len(d.overflow)
			d.overflowMu.Unlock()

			if len(d.pending) == 0 && len(d.workCh) == 0 && overflowCount == 0 {
				d.mu.Unlock()
				close(d.done)
				return
			}
		}

		// --- LOGIQUE DE TIMEOUT ---
		now := time.Now()
		var retryList [][32]byte
		timeoutDetected := false

		for h, t := range d.pending {
			if now.Sub(t) > d.rto {
				d.retries[h]++
				if d.retries[h] > 3 {
					fmt.Printf("⚠️ Timeout définitif sur %x\n", h)
					delete(d.pending, h)
					d.server.UnregisterDatumRequest(h, d.peerAddr)
				} else {
					retryList = append(retryList, h)
					d.pending[h] = now
				}
				timeoutDetected = true
			}
		}

		if timeoutDetected {
			d.onTimeoutDecrease()
		}
		d.mu.Unlock()

		for _, h := range retryList {
			SendDatumRequest(d.server.Conn, d.peerAddr, h)
		}
	}
}

// Analyse le contenu pour trouver les enfants à télécharger
func (d *Downloader) processChildren(datum []byte) {
	typ, content := merkle.ParseDatum(datum)

	switch typ {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(content)
		for _, e := range entries {
			d.queueHash(e.Hash)
		}
	case merkle.TypeBigDirectory, merkle.TypeBig:
		hashes := merkle.ParseBigHashes(content)
		for _, h := range hashes {
			d.queueHash(h)
		}
	}
}

// queueHash ajoute un hash à la file de travail sans jamais le perdre.
// Si le channel est plein, le hash est stocké dans un buffer de débordement
// qui sera vidé par senderLoop.
func (d *Downloader) queueHash(h [32]byte) {
	// On vérifie d'abord si on l'a pas déjà (évite de spammer le channel)
	if _, ok := d.server.Downloads.Get(h); ok {
		return
	}
	select {
	case d.workCh <- h:
	default:
		// Channel plein → stocker dans le buffer de débordement
		d.overflowMu.Lock()
		d.overflow = append(d.overflow, h)
		d.overflowMu.Unlock()
	}
}

// drainOverflow tente de vider le buffer de débordement dans workCh.
// Appelé régulièrement par senderLoop.
func (d *Downloader) drainOverflow() {
	d.overflowMu.Lock()
	if len(d.overflow) == 0 {
		d.overflowMu.Unlock()
		return
	}

	var remaining [][32]byte
	for _, h := range d.overflow {
		// Vérifier si déjà téléchargé entre-temps
		if _, ok := d.server.Downloads.Get(h); ok {
			continue
		}
		select {
		case d.workCh <- h:
		default:
			remaining = append(remaining, h)
		}
	}
	d.overflow = remaining
	d.overflowMu.Unlock()
}

// updateRTTAndWindow met à jour l'estimation RTT (RFC 6298) et ajuste la fenêtre.
// Constantes RFC 6298 :  α = 1/8 (SRTT), β = 1/4 (RTTVAR), K = 4 (RTO)
// Fenêtre : Slow Start (< ssthresh) +2/ACK, Congestion Avoidance (>= ssthresh) +1/ACK
func (d *Downloader) updateRTTAndWindow(sample time.Duration) {
	// 1. Mise à jour RTT (RFC 6298 Sections 2.2 & 2.3)
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

	// 2. RTO = SRTT + 4 * RTTVAR (borné)
	rto := min(max(d.srtt+4*d.rttvar, 50*time.Millisecond), d.timeout)
	d.rto = rto

	// 3. Fenêtre : grandir seulement si latence ≤ moyenne
	if sample <= d.srtt && d.windowSize < d.maxWindowSize {
		if d.windowSize < d.ssthresh {
			d.windowSize += 2
		} else {
			d.windowSize++
		}
		if d.windowSize > d.maxWindowSize {
			d.windowSize = d.maxWindowSize
		}
	}
}

// growWindowOnly ajuste la fenêtre sans toucher au RTT (Karn : paquet retransmis)
func (d *Downloader) growWindowOnly(sample time.Duration) {
	if !d.rttInit {
		return
	}
	if sample <= d.srtt && d.windowSize < d.maxWindowSize {
		if d.windowSize < d.ssthresh {
			d.windowSize += 2
		} else {
			d.windowSize++
		}
		if d.windowSize > d.maxWindowSize {
			d.windowSize = d.maxWindowSize
		}
	}
}

// onTimeoutDecrease réduit la fenêtre (multiplicative decrease) et double le RTO
func (d *Downloader) onTimeoutDecrease() {
	d.ssthresh = utils.MaxInt(d.windowSize/2, d.minWindowSize)
	d.windowSize = utils.MaxInt(d.windowSize/2, d.minWindowSize)
	d.rto = min(d.rto*2, d.timeout)
}

// removeFromPendingDownloader retire un hash de pending et retries
func (d *Downloader) removeFromPendingDownloader(hash [32]byte) {
	delete(d.pending, hash)
	delete(d.retries, hash)
}
