package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"main/internal/crypto"
	"main/internal/merkle"
	"main/internal/peer"
	"main/internal/protocol"
	"main/internal/utils"
	"net"
	"sync"
	"time"
)

type Server struct {
	Conn    *net.UDPConn
	PrivKey *ecdsa.PrivateKey
	MyName  string

	// Composants internes
	PeerManager *peer.PeerManager
	MerkleStore *merkle.Store // Fichiers locaux
	Downloads   *merkle.Store // Fichiers distants
	RootHash    [32]byte

	// Events
	DatumDispatcher *DatumDispatcher
	rootHashChan    chan [32]byte // Canal temporaire pour recevoir la réponse "Root"
	rootHashMu      sync.Mutex

	// Canal pour détecter les réceptions pendant pingSpam
	PingResponseChan chan *net.UDPAddr
	PingResponseMu   sync.Mutex

	// Cache HTTP pour éviter de spammer l'annuaire
	keyCache   map[string][]byte
	keyCacheMu sync.RWMutex

	workerSem chan struct{}

	shutdown chan struct{}
}

func NewServer(conn *net.UDPConn, key *ecdsa.PrivateKey, name string) *Server {
	return &Server{
		Conn:            conn,
		PrivKey:         key,
		MyName:          name,
		PeerManager:     peer.NewPeerManager(),
		MerkleStore:     merkle.NewStore(),
		Downloads:       merkle.NewStore(),
		DatumDispatcher: NewDatumDispatcher(),
		keyCache:        make(map[string][]byte),
		workerSem:       make(chan struct{}, 100), // Limite à 100 workers concurrents
		shutdown:        make(chan struct{}),
	}
}

// ListenLoop : Boucle principale
func (s *Server) ListenLoop(ctx context.Context) {
	buf := make([]byte, 65535) // max buffer

	for {
		n, remote, err := s.Conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Copie nécessaire car buf est écrasé à la prochaine itération
		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		select {
		case s.workerSem <- struct{}{}:
			go func() {
				defer func() { <-s.workerSem }() // Libérer le semaphore
				s.handlePacket(remote, packetData)
			}()
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		}
	}
}

// Stop ferme tout
func (s *Server) Stop() {
	close(s.shutdown)
	s.Conn.Close()
}

// handlePacket : Le gros switch de dispatch
func (s *Server) handlePacket(addr *net.UDPAddr, data []byte) {
	pkt, err := protocol.DecodePacket(data)
	if err != nil {
		return
	}

	// Log de la réception
	typeName := protocol.GetTypeName(pkt.Header.Type)
	// Juste pour éviter les spams de datum
	if (pkt.Header.Type != protocol.Datum) || protocol.Debug_Enable {
		fmt.Printf("📥 Réception %s ← %s (ID: %d)\n", typeName, addr, pkt.Header.ID)
		if pkt.Header.Type == protocol.Datum {
			fmt.Printf("    Header: %+v\n", pkt.Header)
			fmt.Printf("    Body: %x\n", pkt.Body)
			fmt.Printf("    Signature: %x\n", pkt.Signature)
		}
	}

	// Notifier les listeners de pingSpam qu'on a reçu quelque chose
	s.PingResponseMu.Lock()
	if s.PingResponseChan != nil {
		select {
		case s.PingResponseChan <- addr:
		default:
		}
	}
	s.PingResponseMu.Unlock()

	if p, ok := s.PeerManager.GetByAddr(addr); ok {
		s.PeerManager.AddOrUpdate(p.Name, addr, p.PublicKey, p.IsRelay)
	}

	// Dispatch selon le type
	switch pkt.Header.Type {

	// --- PING / OK ---
	case protocol.Ping:
		SendOk(s.Conn, addr, pkt.Header.ID)
	case protocol.Ok:
	// --- HANDSHAKE ---
	case protocol.Hello:
		s.onHello(pkt, addr, false)

	case protocol.HelloReply:
		s.onHello(pkt, addr, true)

	// --- MERKLE TREE ---
	case protocol.RootRequest:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		fmt.Printf("🌳 Demande de root hash de %s\n", addr)
		SendRootReply(s.Conn, addr, s.RootHash, s.PrivKey, pkt.Header.ID)

	case protocol.RootReply:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		s.onRootReply(pkt, addr)

	case protocol.DatumRequest:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		s.onDatumRequest(pkt, addr)

	case protocol.Datum:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		s.onDatum(pkt)

	case protocol.NoDatum:
		// Juste pour info/debug
		// fmt.Printf("Peer %s n'a pas le datum demandé\n", addr)

	// --- NAT TRAVERSAL ---
	case protocol.NatTraversalRequest:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		// On me demande de faire le relais
		s.onNatRequest(pkt, addr)

	case protocol.NatTraversalRequest2:
		if _, ok := s.PeerManager.GetByAddr(addr); !ok {
			SendError(s.Conn, addr, "please hello first", pkt.Header.ID)
			return
		}
		// Le relais me dit de contacter quelqu'un
		s.onNatRequest2(pkt, addr)

	case protocol.Error:
		fmt.Printf("⚠️ Erreur reçue de %s: %s\n", addr, string(pkt.Body))
		if string(pkt.Body) == "please hello first" {
			fmt.Println("🔄 Session perdue, tentative de reconnexion...")
			SendHello(s.Conn, addr, s.MyName, s.PrivKey)
			SendPing(s.Conn, addr)
		}
	}
}

// --- Handlers Spécifiques ---

func (s *Server) onHello(pkt *protocol.Packet, addr *net.UDPAddr, isReply bool) {
	extensions, name, err := protocol.DecodeHelloBody(pkt.Body)
	if err != nil {
		fmt.Printf("❌ Erreur décodage Hello de %s\n", addr)
		return
	}

	// 1. Récup Clé Publique (Cache -> HTTP)
	keyBytes, err := s.getPublicKey(name)
	if err != nil {
		fmt.Printf("Inconnu au bataillon: %s\n", name)
		return
	}
	pubKey := crypto.ParsePublicKey(keyBytes)

	// 2. Vérif Signature
	if !crypto.VerifySignature(pubKey, pkt.DataToSign(), pkt.Signature) {
		fmt.Printf("Bad signature from %s\n", name)
		return
	}

	isRelay := (extensions & protocol.ExtNatTraversalRelay) != 0

	// 3. Enregistrement
	s.PeerManager.AddOrUpdate(name, addr, pubKey, isRelay)

	if isReply {
		fmt.Printf("✅ Connecté à %s (%s)\n", name, addr)
	} else {
		// Si c'est un Hello initial, on répond
		SendHelloReply(s.Conn, addr, s.MyName, s.PrivKey, pkt.Header.ID)
	}
}

func (s *Server) onDatumRequest(pkt *protocol.Packet, addr *net.UDPAddr) {
	hash, err := protocol.DecodeHashBody(pkt.Body)
	if err != nil {
		return
	}

	// fmt.Printf("📦 Demande datum %x... de %s\n", hash[:8], addr)

	// On cherche d'abord en local, sinon dans le cache téléchargé
	data, ok := s.MerkleStore.Get(hash)
	if !ok {
		data, ok = s.Downloads.Get(hash)
	}

	if ok {
		fmt.Printf("✅ Envoi datum %x... à %s\n", hash[:8], addr)
		SendDatum(s.Conn, addr, hash, data, pkt.Header.ID)
	} else {
		fmt.Printf("❌ Datum %x... introuvable, envoi NoDatum à %s\n", hash[:8], addr)
		SendNoDatum(s.Conn, addr, hash, s.PrivKey, pkt.Header.ID)
	}
}

func (s *Server) onDatum(pkt *protocol.Packet) {
	hash, val, err := protocol.DecodeDatumBody(pkt.Body)
	if err != nil {
		return
	}

	// fmt.Printf("📥 Réception datum %x... (%d bytes)\n", hash, len(val))

	// Vérif intégrité
	if sha256.Sum256(val) != hash {
		fmt.Println("❌ Datum corrompu reçu (Hash mismatch)")
		return
	}

	// Stockage
	s.Downloads.Set(hash, val)
	// fmt.Printf("💾 Datum %x... stocké dans Downloads\n", hash[:8])

	// Notification aux downloaders en attente
	s.DatumDispatcher.Dispatch(hash, val)
}

func (s *Server) onRootReply(pkt *protocol.Packet, addr *net.UDPAddr) {
	rootHash, err := protocol.DecodeHashBody(pkt.Body)
	if err != nil {
		return
	}

	fmt.Printf("🌳 Réception root hash %x... de %s\n", rootHash, addr)

	// Vérif signature
	peer, ok := s.PeerManager.GetByAddr(addr)
	if !ok {
		return
	}

	if !crypto.VerifySignature(peer.PublicKey, pkt.DataToSign(), pkt.Signature) {
		return
	}

	// Transmission au channel en attente
	s.rootHashMu.Lock()
	if s.rootHashChan != nil {
		// Non-bloquant au cas où personne n'écoute
		select {
		case s.rootHashChan <- rootHash:
		default:
		}
	}
	s.rootHashMu.Unlock()
}

// Logique NAT (Relais)
func (s *Server) onNatRequest(pkt *protocol.Packet, srcAddr *net.UDPAddr) {
	// Src demande à contacter Target via nous
	targetStruct, err := protocol.DecodeSocketAddress(pkt.Body)
	if err != nil {
		return
	}

	// On vérifie la signature de Src
	p, ok := s.PeerManager.GetByAddr(srcAddr)
	if !ok || !crypto.VerifySignature(p.PublicKey, pkt.DataToSign(), pkt.Signature) {
		fmt.Printf("❌ NatRequest d'un peer inconnu ou mauvaise signature: %s\n", srcAddr)
		return
	}

	// Vérifier si on connaît la cible (si on est connecté avec elle)
	targetAddr := targetStruct.ToUDPAddr()
	targetPeer, targetKnown := s.PeerManager.GetByAddr(targetAddr)

	if !targetKnown {
		// La cible n'est pas dans nos pairs connectés, on ne peut pas relayer
		fmt.Printf("⚠️ NAT: %s demande à contacter %s mais cette cible n'est pas connectée à nous\n", srcAddr, targetAddr)
		SendError(s.Conn, srcAddr, "Cible non connecté", pkt.Header.ID)
		return
	}

	// On dit OK à Src
	SendOk(s.Conn, srcAddr, pkt.Header.ID)

	// On envoie une notif à Target à l'adresse demandée
	fmt.Printf("🔀 NAT: %s veut contacter %s (%s) via nous\n", srcAddr, targetPeer.Name, targetAddr)

	// Envoyer NatTraversalRequest2 à l'adresse spécifique demandée par le source
	SendNatTraversalRequest2(s.Conn, targetAddr, srcAddr, s.PrivKey)

}

func (s *Server) onNatRequest2(pkt *protocol.Packet, relayAddr *net.UDPAddr) {
	// Le Relais nous dit que Src veut nous parler
	srcStruct, err := protocol.DecodeSocketAddress(pkt.Body)
	if err != nil {
		return
	}

	// Vérification de la signature du relais
	relay, ok := s.PeerManager.GetByAddr(relayAddr)
	if !ok || !crypto.VerifySignature(relay.PublicKey, pkt.DataToSign(), pkt.Signature) {
		fmt.Printf("❌ NatRequest2 d'un relais inconnu: %s\n", relayAddr)
		return
	}

	// On dit merci au relais
	SendOk(s.Conn, relayAddr, pkt.Header.ID)

	srcAddr := srcStruct.ToUDPAddr()
	fmt.Printf("🔀 NAT: %s nous demande de pinguer %s\n", relayAddr, srcAddr)

	// Créer un canal pour détecter les réceptions de cette adresse
	responseChan := make(chan *net.UDPAddr, 10)
	s.PingResponseMu.Lock()
	s.PingResponseChan = responseChan
	s.PingResponseMu.Unlock()

	defer func() {
		s.PingResponseMu.Lock()
		s.PingResponseChan = nil
		s.PingResponseMu.Unlock()
	}()

	// Calculer le timeout total avec backoff exponentiel
	count := 3
	totalTimeout := utils.CalExpo2Time(count)

	// Canal pour détecter le succès
	success := make(chan bool, 1)
	stopSending := make(chan bool)

	go func() {
		for {
			select {
			case receivedAddr := <-responseChan:
				if receivedAddr.String() == srcAddr.String() {
					close(stopSending) // Signaler l'arrêt
					select {
					case success <- true:
					default:
					}
					return
				}
			case <-time.After(totalTimeout):
				select {
				case success <- false:
				default:
				}
				return
			}
		}
	}()

	// Envoyer des pings avec backoff exponentiel
	for i := range count {
		select {
		case <-stopSending:
			// Succès détecté, on arrête immédiatement
			<-success
			fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
			return
		default:
			SendPing(s.Conn, srcAddr)

			// Attendre avec backoff exponentiel (sauf après le dernier ping)
			if i < count-1 {
				var waitTime time.Duration
				if i == 0 {
					waitTime = 1 * time.Second
				} else {
					waitTime = time.Duration(1<<uint(i)) * time.Second
				}

				// Attendre avec possibilité d'interruption
				select {
				case <-stopSending:
					<-success
					fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
					return
				case <-time.After(waitTime):
					// Continuer à la prochaine itération
				}
			}
		}
	}

	// Attendre le résultat final
	select {
	case result := <-success:
		if result {
			fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
		} else {
			fmt.Printf("⏱️ Timeout NAT avec %s\n", srcAddr)
		}
	case <-time.After(500 * time.Millisecond):
		fmt.Printf("⏱️ Timeout NAT avec %s\n", srcAddr)
	}
}

// --- Utils ---

func (s *Server) getPublicKey(name string) ([]byte, error) {
	if name == s.MyName {
		return crypto.PublicKeyToBytes(&s.PrivKey.PublicKey), nil
	}

	s.keyCacheMu.RLock()
	if k, ok := s.keyCache[name]; ok {
		s.keyCacheMu.RUnlock()
		return k, nil
	}
	s.keyCacheMu.RUnlock()

	// Appel HTTP (bloquant, mais bon...)
	key, err := GetKey(name)
	if err != nil {
		return nil, err
	}

	s.keyCacheMu.Lock()
	s.keyCache[name] = key
	s.keyCacheMu.Unlock()
	return key, nil
}

// SetRootHashChan permet au menu d'attendre une réponse
func (s *Server) SetRootHashChan(ch chan [32]byte) {
	s.rootHashMu.Lock()
	s.rootHashChan = ch
	s.rootHashMu.Unlock()
}

func (s *Server) SetMerkleRoot(store *merkle.Store, root [32]byte) {
	s.MerkleStore = store
	s.RootHash = root
}

// KeepAlive : Simple loop qui ping les copains
func (s *Server) KeepAlive(serverAddr *net.UDPAddr, interval time.Duration, ctx context.Context) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-ticker.C:
			fmt.Println()
			// 1. Ping le serveur central (IPv4 et v6 si dispo)
			// On force la ré-résolution pour gérer le changement d'IP DNS éventuel
			if addr, err := net.ResolveUDPAddr("udp", protocol.GetServerUDPv6()); err == nil {
				SendPing(s.Conn, addr)
				time.Sleep(1 * time.Microsecond) // Délai pour garantir un ID unique
			}
			if addr, err := net.ResolveUDPAddr("udp", protocol.GetServerUDPv4()); err == nil {
				SendPing(s.Conn, addr)
				time.Sleep(1 * time.Microsecond)
			}

			// 2. Ping tous les pairs connectés (toutes leurs adresses)
			connectedPeers := s.PeerManager.List()
			for _, peerName := range connectedPeers {
				if peerInfo, ok := s.PeerManager.Get(peerName); ok && peerInfo.Name != "jch.irif.fr" {
					for _, addr := range peerInfo.Addrs {
						SendPing(s.Conn, addr)
						time.Sleep(1 * time.Microsecond)
					}
				}
			}

			// 3. Nettoyage
			s.PeerManager.CleanExpired()
		}
	}
}
