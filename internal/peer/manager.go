package peer

import (
	"crypto/ecdsa"
	"net"
	"sync"
	"time"
)

// PeerInfo contient les informations sur un peer
type PeerInfo struct {
	Name      string
	Addr      *net.UDPAddr
	PublicKey *ecdsa.PublicKey
	LastSeen  time.Time
}

// PeerManager gère les associations avec les autres peers
type PeerManager struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo // clé = nom du peer
}

// NewPeerManager crée un nouveau gestionnaire de peers
func NewPeerManager() *PeerManager {
	return &PeerManager{
		peers: make(map[string]*PeerInfo),
	}
}

// AddOrUpdate ajoute ou met à jour un peer
func (pm *PeerManager) AddOrUpdate(name string, addr *net.UDPAddr, pubKey *ecdsa.PublicKey) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.peers[name] = &PeerInfo{
		Name:      name,
		Addr:      addr,
		PublicKey: pubKey,
		LastSeen:  time.Now(),
	}
}

// UpdateLastSeen met à jour le timestamp d'un peer
func (pm *PeerManager) UpdateLastSeen(name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, ok := pm.peers[name]; ok {
		peer.LastSeen = time.Now()
	}
}

// Get récupère les infos d'un peer
func (pm *PeerManager) Get(name string) (*PeerInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peer, ok := pm.peers[name]
	return peer, ok
}

// GetByAddr récupère un peer par son adresse
func (pm *PeerManager) GetByAddr(addr *net.UDPAddr) (*PeerInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, peer := range pm.peers {
		if peer.Addr.String() == addr.String() {
			return peer, true
		}
	}
	return nil, false
}

// Remove supprime un peer
func (pm *PeerManager) Remove(name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.peers, name)
}

// CleanExpired supprime les peers expirés (> 5 minutes sans message)
func (pm *PeerManager) CleanExpired() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	expiry := 5 * time.Minute
	now := time.Now()

	for name, peer := range pm.peers {
		if now.Sub(peer.LastSeen) > expiry {
			delete(pm.peers, name)
		}
	}
}

// List retourne la liste des noms de peers
func (pm *PeerManager) List() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.peers))
	for name := range pm.peers {
		names = append(names, name)
	}
	return names
}
