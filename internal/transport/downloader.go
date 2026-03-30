package transport

import (
	"fmt"
	"main/internal/config"
	"main/internal/merkle"
	"net"
	"sync"
	"time"
)

// Downloader : Gère le téléchargement "en mémoire" (pour explorer l'arbre)
// Contrairement au DiskDownloader, on ne stocke pas les fichiers sur le disque,
// on remplit juste le store "server.Downloads".
type Downloader struct {
	downloadBase

	// Stats de progression
	totalReceived int
	statsMu       sync.Mutex

	// Communication interne
	workCh chan [32]byte // File d'attente des hash à demander

	// Buffer de débordement pour ne jamais perdre de hash
	overflowMu sync.Mutex
	overflow   [][32]byte
}

func NewDownloader(server *Server, peerAddr *net.UDPAddr) *Downloader {
	return &Downloader{
		downloadBase: newDownloadBase(server, peerAddr),
		workCh:       make(chan [32]byte, config.GlobalConfig.Network.MaxQueueSize),
	}
}

// Start lance les workers
func (d *Downloader) Start() {
	d.unsubscribe = d.server.DatumDispatcher.Subscribe(d.onDatumReceived)

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

	close(d.workCh)
	close(d.responseCh)
	d.wg.Wait()

	d.tracker.CleanupAll()
}

// DownloadTree est la méthode bloquante appelée par le Menu
func (d *Downloader) DownloadTree(rootHash [32]byte) {
	fmt.Printf("ℹ️️ Exploration de l'arbre %x...\n", rootHash)

	d.Start()

	d.workCh <- rootHash
	<-d.done

	d.Stop()
	fmt.Println("\n✅ Exploration terminée.")
}

// Callback du dispatcher — retrait immédiat de pending pour éviter les faux timeouts
func (d *Downloader) onDatumReceived(hash [32]byte, _ []byte) {
	d.tracker.OnReceived(hash)
	d.signalResponse(hash)
}

// Worker 1 : Envoie les demandes
func (d *Downloader) senderLoop() {
	defer d.wg.Done()

	for d.running {
		// 0. Vider le buffer de débordement si possible
		d.drainOverflow()

		// 1. Check Window
		if !d.tracker.CanSend() {
			time.Sleep(time.Duration(config.GlobalConfig.Network.SenderWaitMs) * time.Millisecond)
			continue
		}

		// 2. Get Job
		hash, ok := <-d.workCh
		if !ok {
			return
		}

		// 3. Check si on l'a déjà
		if datum, exists := d.server.Downloads.Get(hash); exists {
			d.processChildren(datum)
			continue
		}

		// 4. Check si déjà en cours
		if d.tracker.IsTracked(hash) {
			continue
		}

		// 5. Send (Track enregistre aussi au PendingTracker)
		d.tracker.Track(hash)
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

		if datum, ok := d.server.Downloads.Get(hash); ok {
			d.processChildren(datum)
		}
	}
}

// Worker 3 : Monitor (Timeouts + Détection de fin)
func (d *Downloader) monitorLoop() {
	defer d.wg.Done()

	tick := time.NewTicker(time.Duration(config.GlobalConfig.Network.MonitorIntervalMs) * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		inflightCount := d.tracker.Count()
		queuedCount := len(d.workCh)
		windowSize, rtt, rto := d.tracker.Snapshot()

		d.statsMu.Lock()
		received := d.totalReceived
		d.statsMu.Unlock()

		fmt.Printf("\r%-100s\r", "")
		fmt.Printf("ℹ️️ %d reçus | Vol: %d | File: %d | Fen: %d | RTT: %s | RTO: %s",
			received, inflightCount, queuedCount, windowSize,
			rtt.Round(time.Millisecond), rto.Round(time.Millisecond))

		// Détection de fin
		d.overflowMu.Lock()
		overflowCount := len(d.overflow)
		d.overflowMu.Unlock()

		if inflightCount == 0 && queuedCount == 0 && overflowCount == 0 {
			time.Sleep(time.Duration(config.GlobalConfig.Network.CompletionConfirmDelayMs) * time.Millisecond)

			d.overflowMu.Lock()
			overflowCount = len(d.overflow)
			d.overflowMu.Unlock()

			if d.tracker.Count() == 0 && len(d.workCh) == 0 && overflowCount == 0 {
				close(d.done)
				return
			}
		}

		// Gestion des timeouts via le tracker
		retryList := d.tracker.HandleTimeouts()

		// Retransmission
		d.tracker.RetransmitAll(d.server.Conn, retryList, func(h [32]byte) bool {
			_, exists := d.server.Downloads.Get(h)
			return exists
		})
	}
}

// Analyse le contenu pour trouver les enfants à télécharger
func (d *Downloader) processChildren(datum []byte) {
	for _, h := range merkle.ExtractChildHashes(datum) {
		d.queueHash(h)
	}
}

// queueHash ajoute un hash à la file de travail sans jamais le perdre.
func (d *Downloader) queueHash(h [32]byte) {
	if _, ok := d.server.Downloads.Get(h); ok {
		return
	}
	select {
	case d.workCh <- h:
	case <-d.done:
		return
	default:
		d.overflowMu.Lock()
		d.overflow = append(d.overflow, h)
		d.overflowMu.Unlock()
	}
}

// drainOverflow tente de vider le buffer de débordement dans workCh.
func (d *Downloader) drainOverflow() {
	d.overflowMu.Lock()
	if len(d.overflow) == 0 {
		d.overflowMu.Unlock()
		return
	}

	var remaining [][32]byte
	for _, h := range d.overflow {
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
