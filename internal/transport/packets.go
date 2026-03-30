package transport

import (
	"crypto/ecdsa"
	"fmt"
	"main/internal/crypto"
	"main/internal/protocol"
	"net"
	"sync/atomic"
)

var globalPacketID uint32

func getNextID() uint32 {
	return atomic.AddUint32(&globalPacketID, 1)
}

// sendRaw centralise la logique de construction et d'envoi.
func sendRaw(conn *net.UDPConn, dest *net.UDPAddr, typ uint8, body []byte, key *ecdsa.PrivateKey, replyTo uint32) (uint32, error) {
	// 1. Gestion ID
	id := replyTo
	if id == 0 {
		id = getNextID()
	}

	// 2. Construction Packet
	pkt := &protocol.Packet{
		Header: protocol.Header{
			ID:     id,
			Type:   typ,
			Length: uint16(len(body)),
		},
		Body: body,
	}

	// 3. Signature (si une clé est fournie)
	if key != nil {
		pkt.Signature = crypto.ComputeSignature(key, pkt.DataToSign())
	}

	// 4. Sérialisation
	bytes := pkt.Encode()

	// 5. Envoi
	_, err := conn.WriteToUDP(bytes, dest)
	if err != nil {
		return 0, fmt.Errorf("send error: %v", err)
	}

	// 6. Log de l'envoi
	typeName := protocol.GetTypeName(typ)
	// Pour éviter les spams de datum
	if typ != protocol.DatumRequest || protocol.DebugEnabled {
		fmt.Printf("ℹ️️ Envoi %s → %s (ID: %d)\n", typeName, dest, id)
	}

	return id, nil
}

// --- Messages de Contrôle ---

func SendPing(conn *net.UDPConn, dest *net.UDPAddr) (uint32, error) {
	// Ping n'a pas de corps et pas besoin de signature
	return sendRaw(conn, dest, protocol.Ping, nil, nil, 0)
}

func SendOk(conn *net.UDPConn, dest *net.UDPAddr, replyTo uint32) error {
	_, err := sendRaw(conn, dest, protocol.Ok, nil, nil, replyTo)
	return err
}

func SendError(conn *net.UDPConn, dest *net.UDPAddr, msg string, replyTo uint32) error {
	_, err := sendRaw(conn, dest, protocol.Error, []byte(msg), nil, replyTo)
	return err
}

// --- Handshake ---

func SendHello(conn *net.UDPConn, dest *net.UDPAddr, name string, key *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.HelloMessage{
		Name:       name,
		Extensions: protocol.ExtNatTraversalRelay,
	}
	return sendRaw(conn, dest, protocol.Hello, msg.EncodeBody(), key, 0)
}

func SendHelloReply(conn *net.UDPConn, dest *net.UDPAddr, name string, key *ecdsa.PrivateKey, replyTo uint32) error {
	msg := &protocol.HelloMessage{
		Name:       name,
		Extensions: protocol.ExtNatTraversalRelay,
	}
	_, err := sendRaw(conn, dest, protocol.HelloReply, msg.EncodeBody(), key, replyTo)
	return err
}

// --- Merkle / Data ---

func SendRootRequest(conn *net.UDPConn, dest *net.UDPAddr) (uint32, error) {
	return sendRaw(conn, dest, protocol.RootRequest, nil, nil, 0)
}

func SendRootReply(conn *net.UDPConn, dest *net.UDPAddr, hash [32]byte, key *ecdsa.PrivateKey, replyTo uint32) error {
	msg := &protocol.HashMessage{Hash: hash}
	// RootReply signé pour prouver que le hash vient bien de nous
	_, err := sendRaw(conn, dest, protocol.RootReply, msg.EncodeBody(), key, replyTo)
	return err
}

func SendDatumRequest(conn *net.UDPConn, dest *net.UDPAddr, hash [32]byte) (uint32, error) {
	msg := &protocol.HashMessage{Hash: hash}
	return sendRaw(conn, dest, protocol.DatumRequest, msg.EncodeBody(), nil, 0)
}

func SendDatum(conn *net.UDPConn, dest *net.UDPAddr, hash [32]byte, data []byte, replyTo uint32) error {
	// Pas de signature ici, l'intégrité est garantie par le hash Merkle
	msg := &protocol.DatumMessage{Hash: hash, Value: data}
	_, err := sendRaw(conn, dest, protocol.Datum, msg.EncodeBody(), nil, replyTo)
	return err
}

func SendNoDatum(conn *net.UDPConn, dest *net.UDPAddr, hash [32]byte, key *ecdsa.PrivateKey, replyTo uint32) error {
	// Signé pour éviter qu'un attaquant spamme des "NoDatum"
	msg := &protocol.HashMessage{Hash: hash}
	_, err := sendRaw(conn, dest, protocol.NoDatum, msg.EncodeBody(), key, replyTo)
	return err
}

// --- NAT Traversal ---

func SendNatTraversalRequest(conn *net.UDPConn, relay *net.UDPAddr, target *net.UDPAddr, key *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.NatTraversalMessage{
		Address: *protocol.FromUDPAddr(target),
	}
	return sendRaw(conn, relay, protocol.NatTraversalRequest, msg.EncodeBody(), key, 0)
}

func SendNatTraversalRequest2(conn *net.UDPConn, target *net.UDPAddr, requester *net.UDPAddr, key *ecdsa.PrivateKey) (uint32, error) {
	msg := &protocol.NatTraversalMessage{
		Address: *protocol.FromUDPAddr(requester),
	}
	// On envoie au target l'instruction de ping l'adresse source
	return sendRaw(conn, target, protocol.NatTraversalRequest2, msg.EncodeBody(), key, 0)
}
