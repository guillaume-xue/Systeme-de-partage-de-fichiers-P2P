package peer

import (
	"crypto/ecdsa"
	"main/internal/config"
	"net"
	"sync"
	"time"
)

// Manager gère la liste des connectés
type Manager struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo
}

func NewManager() *Manager {
	return &Manager{
		peers: make(map[string]*PeerInfo),
	}
}

// AddOrUpdate : Heartbeat ou nouvelle connexion
func (m *Manager) AddOrUpdate(name string, addr *net.UDPAddr, pubKey *ecdsa.PublicKey, isRelay bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	isIPv4 := addr.IP.To4() != nil

	if peer, exists := m.peers[name]; exists {
		peer.LastSeen = now
		peer.IsRelay = isRelay

		// Chercher et remplacer l'adresse du même protocole
		found := false
		for i := range peer.Addrs {
			existingIsIPv4 := peer.Addrs[i].Addr.IP.To4() != nil
			if existingIsIPv4 == isIPv4 {
				// Remplacer l'adresse du même protocole
				peer.Addrs[i].Addr = addr
				peer.Addrs[i].LastSeen = now
				found = true
				break
			}
		}
		if !found {
			// Ajouter la nouvelle adresse (protocole différent)
			peer.Addrs = append(peer.Addrs, AddrInfo{
				Addr:     addr,
				LastSeen: now,
			})
		}
	} else {
		// Nouveau peer
		m.peers[name] = &PeerInfo{
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
func (m *Manager) Get(name string) (*PeerInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peer, ok := m.peers[name]
	return peer, ok
}

// GetByAddr récupère un peer par son adresse
func (m *Manager) GetByAddr(addr *net.UDPAddr) (*PeerInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, peer := range m.peers {
		for _, addrInfo := range peer.Addrs {
			if addrInfo.Addr.IP.Equal(addr.IP) && addrInfo.Addr.Port == addr.Port {
				return peer, true
			}
		}
	}
	return nil, false
}

// CleanExpired supprime les peers inactifs et les vieilles adresses
func (m *Manager) CleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	timeout := config.GlobalConfig.Peer.ExpiryTimeout
	now := time.Now()

	for name, peer := range m.peers {
		// Supprimer le peer entièrement s'il est inactif
		if now.Sub(peer.LastSeen) > timeout {
			delete(m.peers, name)
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
			delete(m.peers, name)
		} else {
			peer.Addrs = validAddrs
		}
	}
}

// List retourne la liste des noms de peers
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.peers) == 0 {
		return []string{}
	}

	list := make([]string, 0, len(m.peers))
	for name := range m.peers {
		list = append(list, name)
	}
	return list
}
