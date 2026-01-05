package peer

import (
	"crypto/ecdsa"
	"fmt"
	"log"
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
}

// GetAddr retourne la première adresse (pour compatibilité)
func (p *PeerInfo) GetAddr() *net.UDPAddr {
	if len(p.Addrs) > 0 {
		return p.Addrs[0]
	}
	return nil
}

// AvailablePeerInfo contient les infos basiques d'un pair disponible sur le serveur
type AvailablePeerInfo struct {
	Name       string
	Addresses  string // Format brut retourné par le serveur
	LastUpdate time.Time
}

// PeerManager gère la liste des connectés
type PeerManager struct {
	mu             sync.RWMutex
	peers          map[string]*PeerInfo
	availableMu    sync.RWMutex
	availablePeers map[string]*AvailablePeerInfo // Tous les pairs du serveur HTTP
	shutdown       chan struct{}
	fetchPeersList func() ([]string, error)     // Fonction pour récupérer la liste
	fetchPeerAddr  func(string) (string, error) // Fonction pour récupérer les adresses
}

func NewPeerManager() *PeerManager {
	return &PeerManager{
		peers:          make(map[string]*PeerInfo),
		availablePeers: make(map[string]*AvailablePeerInfo),
		shutdown:       make(chan struct{}),
	}
}

// SetFetchFunctions configure les fonctions pour récupérer les pairs du serveur HTTP
func (pm *PeerManager) SetFetchFunctions(fetchList func() ([]string, error), fetchAddr func(string) (string, error)) {
	pm.fetchPeersList = fetchList
	pm.fetchPeerAddr = fetchAddr
}

// StartAutoRefresh démarre la goroutine qui actualise la liste des pairs disponibles toutes les 3 minutes
func (pm *PeerManager) StartAutoRefresh() {
	if pm.fetchPeersList == nil || pm.fetchPeerAddr == nil {
		log.Println("⚠️ Fonctions de récupération non configurées, auto-refresh désactivé")
		return
	}

	// Première récupération immédiate
	pm.refreshAvailablePeers()

	// Goroutine pour actualiser toutes les 3 minutes
	go func() {
		ticker := time.NewTicker(3 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pm.refreshAvailablePeers()
			case <-pm.shutdown:
				return
			}
		}
	}()
}

// refreshAvailablePeers récupère et met à jour la liste des pairs disponibles
func (pm *PeerManager) refreshAvailablePeers() {
	peerNames, err := pm.fetchPeersList()
	if err != nil {
		log.Printf("❌ Erreur récupération liste des pairs: %v\n", err)
		return
	}

	pm.availableMu.Lock()
	defer pm.availableMu.Unlock()

	// Nettoyer l'ancienne liste
	pm.availablePeers = make(map[string]*AvailablePeerInfo)

	// Récupérer les adresses pour chaque pair
	for _, name := range peerNames {
		addresses, err := pm.fetchPeerAddr(name)
		if err != nil {
			log.Printf("⚠️ Erreur récupération adresses pour %s: %v\n", name, err)
			continue
		}

		pm.availablePeers[name] = &AvailablePeerInfo{
			Name:       name,
			Addresses:  addresses,
			LastUpdate: time.Now(),
		}
	}

	fmt.Printf("🔄 Liste des pairs disponibles actualisée: %d pairs\n", len(pm.availablePeers))
}

// GetAvailablePeers retourne la liste des pairs disponibles sur le serveur
func (pm *PeerManager) GetAvailablePeers() map[string]*AvailablePeerInfo {
	pm.availableMu.RLock()
	defer pm.availableMu.RUnlock()

	// Copie pour éviter les problèmes de concurrence
	copy := make(map[string]*AvailablePeerInfo)
	for name, info := range pm.availablePeers {
		copy[name] = info
	}
	return copy
}

// GetAvailablePeer retourne les infos d'un pair disponible spécifique
func (pm *PeerManager) GetAvailablePeer(name string) (*AvailablePeerInfo, bool) {
	pm.availableMu.RLock()
	defer pm.availableMu.RUnlock()
	info, ok := pm.availablePeers[name]
	return info, ok
}

// Stop arrête la goroutine d'actualisation
func (pm *PeerManager) Stop() {
	close(pm.shutdown)
}

// AddOrUpdate : Heartbeat ou nouvelle connexion
func (pm *PeerManager) AddOrUpdate(name string, addr *net.UDPAddr, pubKey *ecdsa.PublicKey) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, exists := pm.peers[name]; exists {
		peer.LastSeen = time.Now()
		// Ajouter l'adresse si elle n'existe pas déjà
		addrStr := addr.String()
		found := false
		for _, existingAddr := range peer.Addrs {
			if existingAddr.String() == addrStr {
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

	target := addr.String()
	for _, peer := range pm.peers {
		for _, peerAddr := range peer.Addrs {
			if peerAddr.String() == target {
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
