package transport

import (
	"net"
	"sync"
)

// PendingTracker suit les requêtes en attente (anti-injection).
// Empêche d'accepter des réponses non sollicitées.
type PendingTracker struct {
	// Hash → set d'adresses de peers à qui on a demandé ce datum
	datumRequests map[[32]byte]map[string]struct{}
	datumMu       sync.RWMutex

	// Adresses à qui on a envoyé un RootRequest
	rootRequests map[string]struct{}
	rootMu       sync.RWMutex
}

func NewPendingTracker() *PendingTracker {
	return &PendingTracker{
		datumRequests: make(map[[32]byte]map[string]struct{}),
		rootRequests:  make(map[string]struct{}),
	}
}

// --- Datum ---

func (pt *PendingTracker) RegisterDatum(hash [32]byte, addr *net.UDPAddr) {
	pt.datumMu.Lock()
	if pt.datumRequests[hash] == nil {
		pt.datumRequests[hash] = make(map[string]struct{})
	}
	pt.datumRequests[hash][addr.String()] = struct{}{}
	pt.datumMu.Unlock()
}

func (pt *PendingTracker) UnregisterDatum(hash [32]byte, addr *net.UDPAddr) {
	pt.datumMu.Lock()
	if peers, ok := pt.datumRequests[hash]; ok {
		delete(peers, addr.String())
		if len(peers) == 0 {
			delete(pt.datumRequests, hash)
		}
	}
	pt.datumMu.Unlock()
}

func (pt *PendingTracker) IsDatumExpected(hash [32]byte, addr *net.UDPAddr) bool {
	pt.datumMu.RLock()
	peers, ok := pt.datumRequests[hash]
	if ok {
		_, ok = peers[addr.String()]
	}
	pt.datumMu.RUnlock()
	return ok
}

// --- Root ---

func (pt *PendingTracker) RegisterRoot(addr *net.UDPAddr) {
	pt.rootMu.Lock()
	pt.rootRequests[addr.String()] = struct{}{}
	pt.rootMu.Unlock()
}

func (pt *PendingTracker) UnregisterRoot(addr *net.UDPAddr) {
	pt.rootMu.Lock()
	delete(pt.rootRequests, addr.String())
	pt.rootMu.Unlock()
}

func (pt *PendingTracker) IsRootExpected(addr *net.UDPAddr) bool {
	pt.rootMu.RLock()
	_, ok := pt.rootRequests[addr.String()]
	pt.rootMu.RUnlock()
	return ok
}
