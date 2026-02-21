package transport

import (
	"fmt"
	"main/internal/config"
	"net"
	"sync"
	"time"
)

/*
	InflightTracker factorise la gestion des requêtes en vol (inflight),
	des retries, et de la mise à jour RTT (avec algorithme de Karn).
	Partagé entre Downloader et DiskDownloader.
*/

func GetMaxRetries() int {
	return config.GlobalConfig.Network.MaxRetries
}

type InflightTracker struct {
	entries map[[32]byte]time.Time // Hash -> Timestamp d'envoi
	retries map[[32]byte]int       // Hash -> Nombre de retries
	mu      sync.Mutex

	fc      *FlowControl
	pending *PendingTracker
	peer    *net.UDPAddr
}

func NewInflightTracker(fc *FlowControl, pending *PendingTracker, peer *net.UDPAddr) *InflightTracker {
	return &InflightTracker{
		entries: make(map[[32]byte]time.Time),
		retries: make(map[[32]byte]int),
		fc:      fc,
		pending: pending,
		peer:    peer,
	}
}

// Track enregistre un hash comme en vol (inflight)
func (t *InflightTracker) Track(hash [32]byte) {
	t.mu.Lock()
	t.entries[hash] = time.Now()
	t.mu.Unlock()
	t.pending.RegisterDatum(hash, t.peer)
}

// IsTracked vérifie si un hash est en cours de téléchargement
func (t *InflightTracker) IsTracked(hash [32]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[hash]
	return ok
}

// Remove retire un hash de la liste inflight et retourne son timestamp d'envoi
func (t *InflightTracker) Remove(hash [32]byte) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	start := t.entries[hash]
	delete(t.entries, hash)
	delete(t.retries, hash)
	return start
}

// OnReceived est le callback à appeler quand un datum est reçu.
// Met à jour le RTT (avec algorithme de Karn) et retire le hash de inflight.
// Retourne true si le hash était bien en vol.
func (t *InflightTracker) OnReceived(hash [32]byte) bool {
	t.mu.Lock()
	sentAt, ok := t.entries[hash]
	wasRetried := t.retries[hash] > 0
	if ok {
		responseTime := time.Since(sentAt)
		if !wasRetried {
			// Karn : mise à jour RTT uniquement si pas de retransmission
			t.fc.UpdateRTT(responseTime)
		} else {
			t.fc.GrowWindowOnly(responseTime)
		}
		delete(t.entries, hash)
		delete(t.retries, hash)
	}
	t.mu.Unlock()
	return ok
}

// HandleTimeouts parcourt les requêtes en vol, détecte les timeouts,
// et retourne la liste des hashs à retransmettre.
// Les hashs ayant dépassé MaxRetries sont abandonnés.
func (t *InflightTracker) HandleTimeouts() [][32]byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	timeoutCount := 0
	var retryList [][32]byte

	_, _, currentRTO := t.fc.Snapshot()

	for hash, sentAt := range t.entries {
		if now.Sub(sentAt) > currentRTO {
			timeoutCount++
			t.retries[hash]++
			if t.retries[hash] > GetMaxRetries() {
				fmt.Printf("\n⚠️ Abandon définitif %x\n", hash)
				delete(t.entries, hash)
				delete(t.retries, hash)
				t.pending.UnregisterDatum(hash, t.peer)
			} else {
				retryList = append(retryList, hash)
				t.entries[hash] = now // Reset le timer
			}
		}
	}

	// Multiplicative decrease + back-off RTO
	if timeoutCount > 0 {
		t.fc.OnTimeout()
	}

	return retryList
}

// CanSend retourne true si la fenêtre de congestion permet un nouvel envoi
func (t *InflightTracker) CanSend() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fc.CanSend(len(t.entries))
}

// Count retourne le nombre de requêtes en vol
func (t *InflightTracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// CleanupAll désenregistre toutes les requêtes en attente du PendingTracker.
// À appeler lors de l'arrêt du downloader.
func (t *InflightTracker) CleanupAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for hash := range t.entries {
		t.pending.UnregisterDatum(hash, t.peer)
	}
}

// Snapshot retourne les métriques courantes du FlowControl (pour l'affichage).
func (t *InflightTracker) Snapshot() (windowSize int, rtt, rto time.Duration) {
	return t.fc.Snapshot()
}

// RetransmitAll retransmet les hashs donnés en ré-enregistrant au PendingTracker.
// hasProvider permet de vérifier si le datum a été reçu entre-temps.
func (t *InflightTracker) RetransmitAll(conn *net.UDPConn, hashes [][32]byte, hasProvider func([32]byte) bool) {
	for _, h := range hashes {
		if hasProvider(h) {
			t.Remove(h)
			t.pending.UnregisterDatum(h, t.peer)
			continue
		}
		t.pending.RegisterDatum(h, t.peer)
		SendDatumRequest(conn, t.peer, h)
	}
}
