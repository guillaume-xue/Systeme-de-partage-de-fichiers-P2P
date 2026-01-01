package transport

import (
	"crypto/ecdsa"
	"fmt"
	"main/internal/crypto"
	"main/internal/merkle"
	"main/internal/peer"
	"main/internal/protocol"
	"net"
	"sync"
	"time"
)

// Server représente le serveur UDP
type Server struct {
	Conn        *net.UDPConn
	PrivKey     *ecdsa.PrivateKey
	MyName      string
	PeerManager *peer.PeerManager
	MerkleStore *merkle.Store // Nos fichiers partagés (local)
	Downloads   *merkle.Store // Datums téléchargés (distant)
	RootHash    [32]byte

	// Pour suivre les associations en attente
	pendingHellos map[uint32]*net.UDPAddr
	pendingMu     sync.Mutex

	// Cache des clés publiques pour éviter les requêtes HTTP répétées
	keyCache   map[string][]byte
	keyCacheMu sync.RWMutex

	// Canal pour notifier les téléchargements (pour le Downloader)
	OnDatumReceived func(hash [32]byte, datum []byte)

	// Canal pour notifier la réception du root hash
	rootHashChan chan [32]byte

	// Pour l'arrêt propre
	shutdown chan struct{}
	running  bool
}

// NewServer crée un nouveau serveur UDP
func NewServer(conn *net.UDPConn, privKey *ecdsa.PrivateKey, myName string) *Server {
	return &Server{
		Conn:          conn,
		PrivKey:       privKey,
		MyName:        myName,
		PeerManager:   peer.NewPeerManager(),
		MerkleStore:   merkle.NewStore(),
		Downloads:     merkle.NewStore(),
		pendingHellos: make(map[uint32]*net.UDPAddr),
		keyCache:      make(map[string][]byte),
		shutdown:      make(chan struct{}),
		running:       true,
	}
}

// AddServerAsPeer ajoute le serveur central comme peer associé
// Appelé après une connexion réussie pour éviter de devoir se réassocier manuellement
func (s *Server) AddServerAsPeer(serverAddr *net.UDPAddr, serverName string) {
	// Récupérer la clé publique du serveur
	keyBytes, err := s.getPublicKey(serverName)
	if err != nil || len(keyBytes) != 64 {
		return
	}
	pubKey := crypto.ParsePublicKey(keyBytes)
	s.PeerManager.AddOrUpdate(serverName, serverAddr, pubKey)
}

// Stop arrête proprement le serveur
func (s *Server) Stop() {
	if s.running {
		s.running = false
		close(s.shutdown)
		s.Conn.Close()
	}
}

// getPublicKey récupère la clé publique d'un peer (avec cache)
func (s *Server) getPublicKey(peerName string) ([]byte, error) {
	// Si c'est nous-mêmes, retourner notre propre clé publique
	if peerName == s.MyName {
		return crypto.PublicKeyToBytes(&s.PrivKey.PublicKey), nil
	}

	// Vérifier le cache
	s.keyCacheMu.RLock()
	if key, ok := s.keyCache[peerName]; ok {
		s.keyCacheMu.RUnlock()
		return key, nil
	}
	s.keyCacheMu.RUnlock()

	// Récupérer depuis le serveur HTTP
	keyBytes, err := GetKey(peerName)
	if err != nil {
		return nil, err
	}

	// Mettre en cache
	s.keyCacheMu.Lock()
	s.keyCache[peerName] = keyBytes
	s.keyCacheMu.Unlock()

	return keyBytes, nil
}

// SetMerkleRoot définit le hash racine du Merkle tree
func (s *Server) SetMerkleRoot(store *merkle.Store, rootHash [32]byte) {
	s.MerkleStore = store
	s.RootHash = rootHash
}

// ListenLoop boucle principale d'écoute UDP
func (s *Server) ListenLoop() {
	buffer := make([]byte, 4096)
	for s.running {
		n, remoteAddr, err := s.Conn.ReadFromUDP(buffer)
		if err != nil {
			// Vérifier si c'est une fermeture normale
			if !s.running {
				return
			}
			fmt.Println("❌ Erreur lecture UDP:", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		go s.handlePacket(remoteAddr, data)
	}
}

// handlePacket traite un paquet reçu
func (s *Server) handlePacket(remoteAddr *net.UDPAddr, data []byte) {
	// Décoder le paquet avec les structures du protocole
	packet, err := protocol.DecodePacket(data)
	if err != nil {
		return
	}

	// Données à vérifier pour la signature (header + body)
	dataToVerify := packet.DataToSign()

	switch packet.Header.Type {
	case protocol.Hello:
		s.processHello(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	case protocol.HelloReply:
		s.processHelloReply(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	case protocol.Ping:
		SendOk(s.Conn, remoteAddr, packet.Header.ID)
	case protocol.Ok:
		// Silencieux
	case protocol.RootRequest:
		s.processRootRequest(packet.Header.ID, remoteAddr)
	case protocol.RootReply:
		s.processRootReply(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	case protocol.DatumRequest:
		s.processDatumRequest(packet.Header.ID, packet.Body, remoteAddr)
	case protocol.Datum:
		s.processDatum(packet.Header.ID, packet.Body, remoteAddr)
	case protocol.NoDatum:
		s.processNoDatum(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	case protocol.Error:
		fmt.Printf("❌ Erreur de %s: %s\n", remoteAddr, string(packet.Body))
	case protocol.NatTraversalRequest:
		s.processNatTraversalRequest(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	case protocol.NatTraversalRequest2:
		s.processNatTraversalRequest2(packet.Header.ID, packet.Body, packet.Signature, dataToVerify, remoteAddr)
	default:
		// Message inconnu ignoré
	}
}

// processHello traite un message Hello reçu
func (s *Server) processHello(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder le body avec la structure du protocole
	extensions, remoteName, err := protocol.DecodeHelloBody(body)
	if err != nil {
		return
	}
	_ = extensions // Réservé pour extensions futures

	keyBytes, err := s.getPublicKey(remoteName)
	if err != nil || len(keyBytes) != 64 {
		return
	}

	pubKey := crypto.ParsePublicKey(keyBytes)
	if !crypto.VerifySignature(pubKey, dataToVerify, signature) {
		return
	}

	fmt.Printf("🔗 Hello de %s (%s)\n", remoteName, addr)
	s.PeerManager.AddOrUpdate(remoteName, addr, pubKey)
	SendHelloReply(s.Conn, addr, s.MyName, s.PrivKey, id)
}

// processHelloReply traite une réponse HelloReply
func (s *Server) processHelloReply(_ uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder le body avec la structure du protocole
	extensions, remoteName, err := protocol.DecodeHelloBody(body)
	if err != nil {
		return
	}
	_ = extensions // Réservé pour extensions futures

	keyBytes, err := s.getPublicKey(remoteName)
	if err != nil || len(keyBytes) != 64 {
		return
	}

	pubKey := crypto.ParsePublicKey(keyBytes)
	if !crypto.VerifySignature(pubKey, dataToVerify, signature) {
		return
	}

	fmt.Printf("✅ Connecté à %s (%s)\n", remoteName, addr)
	s.PeerManager.AddOrUpdate(remoteName, addr, pubKey)
}

// processRootRequest répond avec notre hash racine
func (s *Server) processRootRequest(id uint32, addr *net.UDPAddr) {
	SendRootReply(s.Conn, addr, s.RootHash, s.PrivKey, id)
}

// processRootReply traite une réponse RootReply
func (s *Server) processRootReply(_ uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder le hash avec la structure du protocole
	rootHash, err := protocol.DecodeHashBody(body)
	if err != nil {
		return
	}

	peerInfo, ok := s.PeerManager.GetByAddr(addr)
	if !ok {
		return
	}

	if !crypto.VerifySignature(peerInfo.PublicKey, dataToVerify, signature) {
		return
	}

	if s.rootHashChan != nil {
		s.rootHashChan <- rootHash
	}

	fmt.Printf("🌳 Root hash de %s: %x\n", peerInfo.Name, rootHash)
}

// processDatumRequest répond avec le datum demandé
func (s *Server) processDatumRequest(id uint32, body []byte, addr *net.UDPAddr) {
	// Décoder le hash demandé
	hash, err := protocol.DecodeHashBody(body)
	if err != nil {
		return
	}

	datum, found := s.MerkleStore.Get(hash)
	if !found {
		datum, found = s.Downloads.Get(hash)
	}

	if found {
		SendDatum(s.Conn, addr, hash, datum, id)
	} else {
		SendNoDatum(s.Conn, addr, hash, s.PrivKey, id)
	}
}

// processDatum traite un Datum reçu
func (s *Server) processDatum(_ uint32, body []byte, _ *net.UDPAddr) {
	// Décoder le datum avec la structure du protocole
	expectedHash, value, err := protocol.DecodeDatumBody(body)
	if err != nil {
		return
	}

	// Vérifier l'intégrité via le hash Merkle
	computedHash := merkle.HashData(value)
	if computedHash != expectedHash {
		return
	}

	s.Downloads.Set(expectedHash, value)

	if s.OnDatumReceived != nil {
		s.OnDatumReceived(expectedHash, value)
	}
}

// processNoDatum traite un NoDatum reçu
func (s *Server) processNoDatum(_ uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder le hash
	_, err := protocol.DecodeHashBody(body)
	if err != nil {
		return
	}

	peerInfo, ok := s.PeerManager.GetByAddr(addr)
	if !ok {
		return
	}

	if !crypto.VerifySignature(peerInfo.PublicKey, dataToVerify, signature) {
		return
	}
}

// processNatTraversalRequest traite une demande de NAT traversal (type 4)
func (s *Server) processNatTraversalRequest(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder l'adresse cible avec la structure du protocole
	socketAddr, err := protocol.DecodeSocketAddress(body)
	if err != nil {
		return
	}
	targetAddr := socketAddr.ToUDPAddr()

	peerInfo, ok := s.PeerManager.GetByAddr(addr)
	if !ok || !crypto.VerifySignature(peerInfo.PublicKey, dataToVerify, signature) {
		return
	}

	SendOk(s.Conn, addr, id)
	SendNatTraversalRequest2(s.Conn, targetAddr, addr, s.PrivKey)
}

// processNatTraversalRequest2 traite une demande de NAT traversal relay (type 5)
// Réponse: envoie Ok à l'expéditeur, puis Ping à l'adresse contenue dans le body
func (s *Server) processNatTraversalRequest2(id uint32, body []byte, signature []byte, _ []byte, addr *net.UDPAddr) {
	if len(signature) != protocol.SignatureSize {
		return
	}

	// Décoder l'adresse cible avec la structure du protocole
	socketAddr, err := protocol.DecodeSocketAddress(body)
	if err != nil {
		return
	}
	targetAddr := socketAddr.ToUDPAddr()

	SendOk(s.Conn, addr, id)
	SendPing(s.Conn, targetAddr)
}

// KeepAlive envoie des Ping périodiques pour maintenir les associations
// Envoie sur les deux adresses du serveur (IPv4 et IPv6) pour garder les deux publiées
func (s *Server) KeepAlive(serverAddr *net.UDPAddr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Résoudre les deux adresses du serveur
	serverAddrV4, _ := net.ResolveUDPAddr("udp", protocol.ServerUDPv4)
	serverAddrV6, _ := net.ResolveUDPAddr("udp", protocol.ServerUDPv6)

	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			// Ping le serveur sur les DEUX adresses pour maintenir les deux IP publiées
			if serverAddrV4 != nil {
				SendPing(s.Conn, serverAddrV4)
			}
			if serverAddrV6 != nil {
				SendPing(s.Conn, serverAddrV6)
			}

			// Nettoyer les peers expirés
			s.PeerManager.CleanExpired()
		}
	}
}

func (s *Server) SetRootHashChan(ch chan [32]byte) {
	s.rootHashChan = ch
}
