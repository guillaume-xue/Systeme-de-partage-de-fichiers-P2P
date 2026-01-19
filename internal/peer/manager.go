package peer

import (
	"crypto/ecdsa"
	"net"
	"sync"
	"time"
)

// AddrInfo contient une adresse et son timestamp
type AddrInfo struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
}

// PeerInfo contient les informations sur un peer
type PeerInfo struct {
	Name      string
	Addrs     []AddrInfo // Support IPv4 et IPv6 avec timestamps
	PublicKey *ecdsa.PublicKey
	LastSeen  time.Time
	IsRelay   bool
}

// GetAddr retourne la première adresse (en général la seule) du pair
func (p *PeerInfo) GetAddr() *net.UDPAddr {
	if len(p.Addrs) > 0 {
		return p.Addrs[0].Addr
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

	now := time.Now()

	if peer, exists := pm.peers[name]; exists {
		peer.LastSeen = now
		peer.IsRelay = isRelay
		// Chercher si l'adresse existe déjà et mettre à jour son LastSeen
		found := false
		for i := range peer.Addrs {
			if peer.Addrs[i].Addr.IP.Equal(addr.IP) && peer.Addrs[i].Addr.Port == addr.Port {
				peer.Addrs[i].LastSeen = now
				found = true
				break
			}
		}
		if !found {
			peer.Addrs = append(peer.Addrs, AddrInfo{
				Addr:     addr,
				LastSeen: now,
			})
		}
	} else {
		// Nouveau peer
		pm.peers[name] = &PeerInfo{
			Name: name,
			Addrs: []AddrInfo{{
				Addr:     addr,
				LastSeen: now,
			}},
			PublicKey: pubKey,
			LastSeen:  now,
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
		for _, addrInfo := range peer.Addrs {
			if addrInfo.Addr.IP.Equal(addr.IP) && addrInfo.Addr.Port == addr.Port {
				return peer, true
			}
		}
	}
	return nil, false
}

// CleanExpired supprime les peers inactifs et les vieilles adresses
func (pm *PeerManager) CleanExpired() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	timeout := 5 * time.Minute
	now := time.Now()

	for name, peer := range pm.peers {
		// Supprimer le peer entièrement s'il est inactif
		if now.Sub(peer.LastSeen) > timeout {
			delete(pm.peers, name)
			continue
		}

		// Nettoyer les vieilles adresses du peer
		validAddrs := make([]AddrInfo, 0, len(peer.Addrs))
		for _, addrInfo := range peer.Addrs {
			if now.Sub(addrInfo.LastSeen) <= timeout {
				validAddrs = append(validAddrs, addrInfo)
			}
		}

		// Si toutes les adresses sont expirées, supprimer le peer
		if len(validAddrs) == 0 {
			delete(pm.peers, name)
		} else {
			peer.Addrs = validAddrs
		}
	}
}

// List retourne la liste des noms de peers
func (pm *PeerManager) List() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.peers) == 0 {
		return []string{}
	}

	list := make([]string, 0, len(pm.peers))
	for name := range pm.peers {
		list = append(list, name)
	}
	return list
}
