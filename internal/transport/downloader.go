package transport

import (
	"fmt"
	"main/internal/config"
	"main/internal/merkle"
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
	successCount  int // Compteur de succès consécutifs
	failureCount  int // Compteur d'échecs récents
	statsMu       sync.Mutex

	// Communication interne
	workCh     chan [32]byte // File d'attente des hash à demander
	responseCh chan [32]byte // Signal de réception

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

		pending: make(map[[32]byte]time.Time),
		retries: make(map[[32]byte]int),

		// Buffer large pour ne pas bloquer l'exploration récursive
		workCh:     make(chan [32]byte, 10000),
		responseCh: make(chan [32]byte, 100),

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
	go d.timeoutLoop()
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

	// Boucle d'attente active ("Surcharge wait" avec sleep)
	// Tant qu'il y a des trucs en cours ou dans la file, on attend.
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		<-ticker.C

		d.mu.Lock()
		inflight := len(d.pending)
		windowSize := d.windowSize
		d.mu.Unlock()

		queued := len(d.workCh)

		d.statsMu.Lock()
		received := d.totalReceived
		d.statsMu.Unlock()

		// Affichage de progression - nettoyer la ligne d'abord
		fmt.Printf("\r%-100s\r", "") // Nettoyer avec 100 espaces
		fmt.Printf("📊 Progression: %d reçus | En cours: %d | File d'attente: %d | Fenêtre: %d",
			received, inflight, queued, windowSize)

		if inflight == 0 && queued == 0 {
			// Petite sécurité supplémentaire
			time.Sleep(100 * time.Millisecond)
			if len(d.pending) == 0 && len(d.workCh) == 0 {
				fmt.Println() // Retour à la ligne final
				break
			}
		}
	}

	d.Stop()
	fmt.Println("\n✅ Exploration terminée.")
}

// Callback du dispatcher
func (d *Downloader) onDatumReceived(hash [32]byte, _ []byte) {
	// On envoie juste le signal, le worker traitera
	select {
	case d.responseCh <- hash:
	default:
		// Si channel plein, c'est pas grave, le timeout gérera ou le prochain paquet
	}
}

// Worker 1 : Envoie les demandes
func (d *Downloader) senderLoop() {
	defer d.wg.Done()

	for d.running {
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
			// On l'a déjà, mais il faut peut-être explorer ses enfants !
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

		// 5. Send
		SendDatumRequest(d.server.Conn, d.peerAddr, hash)
	}
}

// Worker 2 : Traite les réceptions
func (d *Downloader) responseLoop() {
	defer d.wg.Done()

	for hash := range d.responseCh {
		d.mu.Lock()
		sentAt, ok := d.pending[hash]
		if ok {
			// Succès ! Incrémenter le compteur
			d.successCount++
			d.failureCount = 0 // Reset les échecs

			// Augmenter la fenêtre seulement si réponse rapide
			if time.Since(sentAt) < d.timeout/2 && d.windowSize < d.maxWindowSize {
				d.windowSize++
			}
			delete(d.pending, hash)
			delete(d.retries, hash)
		}
		d.mu.Unlock()

		// Incrémenter les stats
		d.statsMu.Lock()
		d.totalReceived++
		d.statsMu.Unlock()

		// Si on a reçu le datum, il faut aller chercher ses enfants
		// (Récursion pour tout télécharger)
		if datum, ok := d.server.Downloads.Get(hash); ok {
			d.processChildren(datum)
		}
	}
}

// Worker 3 : Gère les timeouts et retransmissions
func (d *Downloader) timeoutLoop() {
	defer d.wg.Done()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for d.running {
		<-tick.C

		now := time.Now()
		var retryList [][32]byte

		d.mu.Lock()
		for h, t := range d.pending {
			if now.Sub(t) > d.timeout {
				d.retries[h]++
				if d.retries[h] > 3 {
					// Trop d'essais, on lâche l'affaire pour ce noeud
					fmt.Printf("⚠️ Timeout définitif sur %x\n", h)
					delete(d.pending, h)
				} else {
					retryList = append(retryList, h)
					d.pending[h] = now // Reset timer
				}
			}
		}

		// Ajuster la fenêtre seulement si taux d'échec significatif
		if len(retryList) > 0 {
			d.failureCount += len(retryList)
			d.successCount = 0 // Reset succès après échec

			// Diminuer la fenêtre seulement si échecs répétés
			if d.failureCount > 2 && d.windowSize > d.minWindowSize {
				// Réduction standard : -40% (TCP-like)
				newWindow := (d.windowSize * 3) / 5
				d.windowSize = utils.MaxInt(newWindow, d.minWindowSize)
				d.failureCount = 0 // Reset après ajustement
			}
		}
		d.mu.Unlock()

		// Retransmission
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
		// Pour les BigNodes, le contenu c'est juste des hashs
		hashes := merkle.ParseBigHashes(content)
		for _, h := range hashes {
			d.queueHash(h)
		}

		// TypeChunk : rien à faire, c'est une feuille (bout de fichier)
	}
}

// Helper pour ajouter à la file sans bloquer
func (d *Downloader) queueHash(h [32]byte) {
	// On vérifie d'abord si on l'a pas déjà (évite de spammer le channel)
	if _, ok := d.server.Downloads.Get(h); ok {
		return
	}

	select {
	case d.workCh <- h:
	default:
		// fmt.Println("Queue full!")
	}
}
