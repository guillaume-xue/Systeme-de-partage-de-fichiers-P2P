package transport

import (
	"crypto/ecdsa"
	"fmt"
	"main/internal/crypto"
	"main/internal/protocol"
	"net"
	"time"
)

// buildPacket construit un paquet UDP complet avec signature optionnelle
func buildPacket(id uint32, msgType uint8, body []byte, privKey *ecdsa.PrivateKey) []byte {
	packet := &protocol.Packet{
		Header: protocol.Header{
			ID:     id,
			Type:   msgType,
			Length: uint16(len(body)),
		},
		Body: body,
	}

	if privKey != nil {
		packet.Signature = crypto.ComputeSignature(privKey, packet.DataToSign())
	}

	return packet.Encode()
}

// generatePacketID génère un ID de paquet unique basé sur l'horodatage
func generatePacketID() uint32 {
	return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
}

// SendHello envoie un message Hello pour initier une association (doit être signé)
func SendHello(conn *net.UDPConn, destAddr *net.UDPAddr, myName string, privKey *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.HelloMessage{
		Extensions: 0,
		Name:       myName,
	}

	id := generatePacketID()
	packet := buildPacket(id, protocol.Hello, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi Hello: %w", err)
	}

	return id, nil
}

// SendHelloReply envoie une réponse HelloReply (doit être signé)
func SendHelloReply(conn *net.UDPConn, destAddr *net.UDPAddr, myName string, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	msg := &protocol.HelloMessage{
		Extensions: 0,
		Name:       myName,
	}

	packet := buildPacket(replyToID, protocol.HelloReply, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi HelloReply: %w", err)
	}

	return nil
}

// SendPing envoie un message Ping pour maintenir l'association (sans signature)
func SendPing(conn *net.UDPConn, destAddr *net.UDPAddr) (uint32, error) {
	id := generatePacketID()
	packet := buildPacket(id, protocol.Ping, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi Ping: %w", err)
	}

	return id, nil
}

// SendOk envoie une réponse Ok à un Ping (sans signature)
func SendOk(conn *net.UDPConn, destAddr *net.UDPAddr, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.Ok, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi Ok: %w", err)
	}

	return nil
}

// SendRootRequest demande le hash racine du Merkle tree d'un peer
func SendRootRequest(conn *net.UDPConn, destAddr *net.UDPAddr) (uint32, error) {
	id := generatePacketID()
	packet := buildPacket(id, protocol.RootRequest, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi RootRequest: %w", err)
	}

	return id, nil
}

// SendRootReply envoie le hash racine (doit être signé)
func SendRootReply(conn *net.UDPConn, destAddr *net.UDPAddr, rootHash [32]byte, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	msg := &protocol.HashMessage{Hash: rootHash}

	packet := buildPacket(replyToID, protocol.RootReply, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi RootReply: %w", err)
	}

	return nil
}

// SendDatumRequest demande un datum par son hash
func SendDatumRequest(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte) (uint32, error) {
	msg := &protocol.HashMessage{Hash: hash}

	id := generatePacketID()
	packet := buildPacket(id, protocol.DatumRequest, msg.EncodeBody(), nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi DatumRequest: %w", err)
	}

	return id, nil
}

// SendDatum envoie un datum (sans signature - protégé par le hash Merkle)
func SendDatum(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte, value []byte, replyToID uint32) error {
	msg := &protocol.DatumMessage{Hash: hash, Value: value}

	packet := buildPacket(replyToID, protocol.Datum, msg.EncodeBody(), nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi Datum: %w", err)
	}

	return nil
}

// SendNoDatum signale qu'on n'a pas le datum demandé (doit être signé)
func SendNoDatum(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	msg := &protocol.HashMessage{Hash: hash}

	packet := buildPacket(replyToID, protocol.NoDatum, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi NoDatum: %w", err)
	}

	return nil
}

// SendError envoie un message d'erreur
func SendError(conn *net.UDPConn, destAddr *net.UDPAddr, errorMsg string, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.Error, []byte(errorMsg), nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("❌ erreur envoi Error: %w", err)
	}

	return nil
}

// SendNatTraversalRequest envoie une demande de NAT traversal à un intermédiaire
// Le serveur relayera la demande au peer cible (doit être signé)
func SendNatTraversalRequest(conn *net.UDPConn, relayAddr *net.UDPAddr, targetAddr *net.UDPAddr, privKey *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.NatTraversalMessage{
		Address: *protocol.FromUDPAddr(targetAddr),
	}

	id := generatePacketID()
	packet := buildPacket(id, protocol.NatTraversalRequest, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, relayAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi NatTraversalRequest: %w", err)
	}

	return id, nil
}

// SendNatTraversalRequest2 envoie une demande relay au peer cible (doit être signé)
// Envoyé par un intermédiaire pour demander au peer de nous envoyer un Ping
func SendNatTraversalRequest2(conn *net.UDPConn, targetAddr *net.UDPAddr, requesterAddr *net.UDPAddr, privKey *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.NatTraversalMessage{
		Address: *protocol.FromUDPAddr(requesterAddr),
	}

	id := generatePacketID()
	packet := buildPacket(id, protocol.NatTraversalRequest2, msg.EncodeBody(), privKey)

	_, err := conn.WriteToUDP(packet, targetAddr)
	if err != nil {
		return 0, fmt.Errorf("❌ erreur envoi NatTraversalRequest2: %w", err)
	}

	return id, nil
}
