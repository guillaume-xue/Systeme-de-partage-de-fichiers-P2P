package transport

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
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
			fmt.Println("Erreur lecture:", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		go s.handlePacket(remoteAddr, data)
	}
}

// handlePacket traite un paquet reçu
func (s *Server) handlePacket(remoteAddr *net.UDPAddr, data []byte) {
	if len(data) < 7 {
		return
	}

	reader := bytes.NewReader(data[:7])
	var id uint32
	var msgType uint8
	var length uint16

	binary.Read(reader, binary.BigEndian, &id)
	binary.Read(reader, binary.BigEndian, &msgType)
	binary.Read(reader, binary.BigEndian, &length)

	if len(data) < 7+int(length) {
		return
	}

	body := data[7 : 7+int(length)]

	var signature []byte
	if len(data) >= 7+int(length)+64 {
		signature = data[7+int(length) : 7+int(length)+64]
	}

	// Données à vérifier pour la signature (header + body)
	dataToVerify := data[:7+int(length)]

	switch msgType {
	case protocol.Hello:
		s.processHello(id, body, signature, dataToVerify, remoteAddr)
	case protocol.HelloReply:
		s.processHelloReply(id, body, signature, dataToVerify, remoteAddr)
	case protocol.Ping:
		SendOk(s.Conn, remoteAddr, id)
	case protocol.Ok:
		// Silencieux
	case protocol.RootRequest:
		s.processRootRequest(id, remoteAddr)
	case protocol.RootReply:
		s.processRootReply(id, body, signature, dataToVerify, remoteAddr)
	case protocol.DatumRequest:
		s.processDatumRequest(id, body, remoteAddr)
	case protocol.Datum:
		s.processDatum(id, body, remoteAddr)
	case protocol.NoDatum:
		s.processNoDatum(id, body, signature, dataToVerify, remoteAddr)
	case protocol.Error:
		fmt.Printf("❌ Erreur de %s: %s\n", remoteAddr, string(body))
	case protocol.NatTraversalRequest:
		s.processNatTraversalRequest(id, body, signature, dataToVerify, remoteAddr)
	case protocol.NatTraversalRequest2:
		s.processNatTraversalRequest2(id, body, signature, dataToVerify, remoteAddr)
	default:
		// Message inconnu ignoré
	}
}

// processHello traite un message Hello reçu
func (s *Server) processHello(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(body) < 4 || len(signature) != 64 {
		return
	}

	extensions := binary.BigEndian.Uint32(body[:4])
	remoteName := string(body[4:])
	_ = extensions // Utilisé pour compatibilité

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
func (s *Server) processHelloReply(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(body) < 4 || len(signature) != 64 {
		return
	}

	extensions := binary.BigEndian.Uint32(body[:4])
	remoteName := string(body[4:])
	_ = extensions

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
func (s *Server) processRootReply(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(body) != 32 || len(signature) != 64 {
		return
	}

	var rootHash [32]byte
	copy(rootHash[:], body)

	peerInfo, ok := s.PeerManager.GetByAddr(addr)
	if !ok {
		return
	}

	if !crypto.VerifySignature(peerInfo.PublicKey, dataToVerify, signature) {
		return
	}

	fmt.Printf("🌳 Root hash de %s: %x\n", peerInfo.Name, rootHash)
}

// processDatumRequest répond avec le datum demandé
func (s *Server) processDatumRequest(id uint32, body []byte, addr *net.UDPAddr) {
	if len(body) != 32 {
		return
	}

	var hash [32]byte
	copy(hash[:], body)

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
func (s *Server) processDatum(id uint32, body []byte, addr *net.UDPAddr) {
	if len(body) < 33 {
		return
	}

	var expectedHash [32]byte
	copy(expectedHash[:], body[:32])
	value := body[32:]

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
func (s *Server) processNoDatum(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	if len(body) != 32 || len(signature) != 64 {
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
// Format du body selon 4.1.6: 6 octets (IPv4) ou 18 octets (IPv6)
func (s *Server) processNatTraversalRequest(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	// Valider la taille du body: doit être exactement 6 (IPv4) ou 18 (IPv6) octets
	if (len(body) != 6 && len(body) != 18) || len(signature) != 64 {
		return
	}

	// Décoder l'adresse cible selon la taille
	var targetAddr *net.UDPAddr
	if len(body) == 6 {
		// IPv4: [0-3] IP, [4-5] port
		ip := net.IPv4(body[0], body[1], body[2], body[3])
		port := int(binary.BigEndian.Uint16(body[4:6]))
		targetAddr = &net.UDPAddr{IP: ip, Port: port}
	} else {
		// IPv6: [0-15] IP, [16-17] port
		ip := net.IP(body[:16])
		port := int(binary.BigEndian.Uint16(body[16:18]))
		targetAddr = &net.UDPAddr{IP: ip, Port: port}
	}

	peerInfo, ok := s.PeerManager.GetByAddr(addr)
	if !ok || !crypto.VerifySignature(peerInfo.PublicKey, dataToVerify, signature) {
		return
	}

	SendOk(s.Conn, addr, id)
	SendNatTraversalRequest2(s.Conn, targetAddr, addr, s.PrivKey)
}

// processNatTraversalRequest2 traite une demande de NAT traversal relay (type 5)
// Format du body selon 4.1.6: 6 octets (IPv4) ou 18 octets (IPv6)
// Réponse: envoie Ok à l'expéditeur, puis Ping à l'adresse contenue dans le body
func (s *Server) processNatTraversalRequest2(id uint32, body []byte, signature []byte, dataToVerify []byte, addr *net.UDPAddr) {
	// Valider la taille du body: doit être exactement 6 (IPv4) ou 18 (IPv6) octets
	if (len(body) != 6 && len(body) != 18) || len(signature) != 64 {
		return
	}

	// Décoder l'adresse cible selon la taille
	var targetAddr *net.UDPAddr
	if len(body) == 6 {
		// IPv4: [0-3] IP, [4-5] port
		ip := net.IPv4(body[0], body[1], body[2], body[3])
		port := int(binary.BigEndian.Uint16(body[4:6]))
		targetAddr = &net.UDPAddr{IP: ip, Port: port}
	} else {
		// IPv6: [0-15] IP, [16-17] port
		ip := net.IP(body[:16])
		port := int(binary.BigEndian.Uint16(body[16:18]))
		targetAddr = &net.UDPAddr{IP: ip, Port: port}
	}

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
