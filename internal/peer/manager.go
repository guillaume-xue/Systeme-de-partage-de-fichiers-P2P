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
	Addrs     []*net.UDPAddr // Support IPv4 et IPv6
	PublicKey *ecdsa.PublicKey
	LastSeen  time.Time
	IsRelay   bool
}

// GetAddr retourne la première adresse (pour compatibilité)
func (p *PeerInfo) GetAddr() *net.UDPAddr {
	if len(p.Addrs) > 0 {
		return p.Addrs[0]
	}
	return nil
}

// PeerManager gère la liste des connectés
type PeerManager struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo
}

func NewPeerManager() *PeerManager {
	return &PeerManager{
		peers: make(map[string]*PeerInfo),
	}
}

// AddOrUpdate : Heartbeat ou nouvelle connexion
func (pm *PeerManager) AddOrUpdate(name string, addr *net.UDPAddr, pubKey *ecdsa.PublicKey, isRelay bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, exists := pm.peers[name]; exists {
		peer.LastSeen = time.Now()
		peer.IsRelay = isRelay
		// Ajouter l'adresse si elle n'existe pas déjà
		found := false
		for _, existingAddr := range peer.Addrs {
			if existingAddr.Port != addr.Port {
				continue
			}
			if existingAddr.IP.Equal(addr.IP) {
				found = true
				break
			}
		}
		if !found {
			peer.Addrs = append(peer.Addrs, addr)
		}
	} else {
		// Nouveau peer
		pm.peers[name] = &PeerInfo{
			Name:      name,
			Addrs:     []*net.UDPAddr{addr},
			PublicKey: pubKey,
			LastSeen:  time.Now(),
			IsRelay:   isRelay,
		}
	}
}

// Get récupère les infos d'un peer par son nom
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
		for _, peerAddr := range peer.Addrs {
			if peerAddr.Port != addr.Port {
				continue
			}
			if peerAddr.IP.Equal(addr.IP) {
				return peer, true
			}
		}
	}
	return nil, false
}

// CleanExpired supprime les peers inactifs (> 5 minutes sans message)
func (pm *PeerManager) CleanExpired() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	timeout := 5 * time.Minute
	now := time.Now()
	for name, peer := range pm.peers {
		if now.Sub(peer.LastSeen) > timeout {
			delete(pm.peers, name)
		}
	}
}

// List retourne la liste des noms de peers
func (pm *PeerManager) List() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	list := make([]string, 0, len(pm.peers))
	for name := range pm.peers {
		list = append(list, name)
	}
	return list
}
