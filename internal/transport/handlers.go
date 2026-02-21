package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"main/internal/crypto"
	"main/internal/merkle"
	"main/internal/protocol"
	"net"
	"time"
)

// handlePacket : Le gros switch de dispatch
func (s *Server) handlePacket(addr *net.UDPAddr, data []byte) {
	pkt, err := protocol.DecodePacket(data)
	if err != nil {
		return
	}

	// Log de la réception
	typeName := protocol.GetTypeName(pkt.Header.Type)
	// Juste pour éviter les spams de datum
	if (pkt.Header.Type != protocol.Datum) || protocol.DebugEnabled {
		fmt.Printf("ℹ️️ Réception %s ← %s (ID: %d)\n", typeName, addr, pkt.Header.ID)
		if pkt.Header.Type == protocol.Datum {
			fmt.Printf("    Header: %+v\n", pkt.Header)
			fmt.Printf("    Body: %x\n", pkt.Body[:8])
			fmt.Printf("    Signature: %x\n", pkt.Signature[:8])
		}
	}

	// Notifier les listeners de pingSpam qu'on a reçu quelque chose
	s.PingResponseMu.Lock()
	for _, ch := range s.PingResponseChans {
		select {
		case ch <- addr:
		default:
		}
	}
	s.PingResponseMu.Unlock()

	if p, ok := s.Manager.GetByAddr(addr); ok && p != nil {
		s.Manager.AddOrUpdate(p.Name, addr, p.PublicKey, p.IsRelay)
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

	// --- Types nécessitant une authentification ---
	case protocol.RootRequest, protocol.RootReply, protocol.DatumRequest,
		protocol.Datum, protocol.NatTraversalRequest, protocol.NatTraversalRequest2:
		if !s.requireAuth(addr, pkt.Header.ID) {
			return
		}
		switch pkt.Header.Type {
		case protocol.RootRequest:
			s.onRootRequest(pkt, addr)
		case protocol.RootReply:
			s.onRootReply(pkt, addr)
		case protocol.DatumRequest:
			s.onDatumRequest(pkt, addr)
		case protocol.Datum:
			s.onDatum(pkt, addr)
		case protocol.NatTraversalRequest:
			s.onNatRequest(pkt, addr)
		case protocol.NatTraversalRequest2:
			s.onNatRequest2(pkt, addr)
		}

	case protocol.NoDatum:
		if protocol.DebugEnabled {
			fmt.Printf("Peer %s n'a pas le datum demandé\n", addr)
		}

	case protocol.Error:
		fmt.Printf("⚠️ Erreur reçue de %s: %s\n", addr, string(pkt.Body))
		if string(pkt.Body) == "please hello first" {
			fmt.Println("ℹ️️ Session perdue, tentative de reconnexion...")
			SendHello(s.Conn, addr, s.MyName, s.PrivKey)
			SendPing(s.Conn, addr)
		}
	}
}

// requireAuth vérifie que le peer est authentifié (a fait un Hello).
// Envoie une erreur et retourne false sinon.
func (s *Server) requireAuth(addr *net.UDPAddr, pktID uint32) bool {
	if _, ok := s.Manager.GetByAddr(addr); !ok {
		SendError(s.Conn, addr, "please hello first", pktID)
		return false
	}
	return true
}

func (s *Server) onRootRequest(pkt *protocol.Packet, addr *net.UDPAddr) {
	fmt.Printf("ℹ️️ Demande de root hash de %s\n", addr)
	s.mu.RLock()
	rootHash := s.RootHash
	s.mu.RUnlock()
	SendRootReply(s.Conn, addr, rootHash, s.PrivKey, pkt.Header.ID)
}

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
	s.Manager.AddOrUpdate(name, addr, pubKey, isRelay)

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

	// On cherche d'abord en local, sinon dans le cache téléchargé
	s.mu.RLock()
	data, ok := s.MerkleStore.Get(hash)
	s.mu.RUnlock()
	if !ok {
		data, ok = s.Downloads.Get(hash)
	}

	if ok {
		if protocol.DebugEnabled {
			fmt.Printf("ℹ️️ Envoi datum %x... à %s\n", hash, addr)
		}
		SendDatum(s.Conn, addr, hash, data, pkt.Header.ID)
	} else {
		fmt.Printf("ℹ️️ Datum %x... introuvable, envoi NoDatum à %s\n", hash, addr)
		SendNoDatum(s.Conn, addr, hash, s.PrivKey, pkt.Header.ID)
	}
}

func (s *Server) onDatum(pkt *protocol.Packet, addr *net.UDPAddr) {
	hash, val, err := protocol.DecodeDatumBody(pkt.Body)
	if err != nil {
		return
	}

	// Vérifier qu'on a bien demandé ce datum à CE peer
	if !s.Pending.IsDatumExpected(hash, addr) {
		// Si on a déjà ce datum, c'est un doublon inoffensif
		// (réponse tardive suite à un retry dont l'original est arrivé entre-temps)
		if _, alreadyHave := s.Downloads.Get(hash); alreadyHave {
			return
		}
		fmt.Printf("⚠️ Datum non sollicité reçu de %s (hash %x...), ignoré\n", addr, hash[:8])
		return
	}

	// Vérif intégrité
	if sha256.Sum256(val) != hash {
		fmt.Println("❌ Datum corrompu reçu (Hash mismatch)")
		return
	}

	// Retirer des requêtes en attente (on ne l'attend plus)
	s.Pending.UnregisterDatum(hash, addr)

	// Stockage (idempotent si doublon, pas grave)
	s.Downloads.Set(hash, val)

	// Notification aux downloaders en attente
	s.DatumDispatcher.Dispatch(hash, val)
}

func (s *Server) onRootReply(pkt *protocol.Packet, addr *net.UDPAddr) {
	rootHash, err := protocol.DecodeHashBody(pkt.Body)
	if err != nil {
		return
	}

	// Vérifier qu'on a bien demandé un RootRequest à ce peer
	if !s.Pending.IsRootExpected(addr) {
		fmt.Printf("⚠️ RootReply non sollicité de %s, ignoré\n", addr)
		return
	}

	fmt.Printf("ℹ️️ Réception root hash %x... de %s\n", rootHash, addr)

	// Retirer des requêtes en attente
	s.Pending.UnregisterRoot(addr)

	// Vérif signature
	peer, ok := s.Manager.GetByAddr(addr)
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

// --- Utils ---

func (s *Server) getPublicKey(name string) ([]byte, error) {
	if name == s.MyName {
		return crypto.PublicKeyToBytes(&s.PrivKey.PublicKey), nil
	}

	if k, ok := s.keyCache.Get(name); ok {
		return k, nil
	}

	// Appel HTTP (bloquant, mais bon...)
	key, err := GetKey(name)
	if err != nil {
		return nil, err
	}

	s.keyCache.Set(name, key)
	return key, nil
}

// SetRootHashChan permet au menu d'attendre une réponse
func (s *Server) SetRootHashChan(ch chan [32]byte) {
	s.rootHashMu.Lock()
	s.rootHashChan = ch
	s.rootHashMu.Unlock()
}

func (s *Server) SetMerkleRoot(store *merkle.Store, root [32]byte) {
	s.mu.Lock()
	s.MerkleStore = store
	s.RootHash = root
	s.mu.Unlock()
}

// KeepAlive : Simple loop qui ping les copains et le serveur central
func (s *Server) KeepAlive(ctx context.Context, serverAddr *net.UDPAddr, interval time.Duration) {
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
			// Ping le serveur central pour maintenir la session
			SendPing(s.Conn, serverAddr)

			connectedPeers := s.Manager.List()
			for _, peerName := range connectedPeers {
				if peerInfo, ok := s.Manager.Get(peerName); ok {
					for _, addrInfo := range peerInfo.Addrs {
						SendPing(s.Conn, addrInfo.Addr)
						time.Sleep(1 * time.Millisecond)
					}
				}
			}
			s.Manager.CleanExpired()
		}
	}
}
