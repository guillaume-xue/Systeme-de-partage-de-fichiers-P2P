package protocol

import (
	"net"
)

const (
	HeaderSize    = 7
	SignatureSize = 64
)

// Header : En-tête fixe [ID:4][Type:1][Len:2]
type Header struct {
	ID     uint32
	Type   uint8
	Length uint16
}

// HelloMessage (Type 1 & 130)
type HelloMessage struct {
	Extensions uint32
	Name       string
}

// DatumMessage (Type 132) : [Hash:32][Value...]
type DatumMessage struct {
	Hash  [32]byte
	Value []byte
}

// HashMessage (Type 2, 3, 131, 133) : [Hash:32]
type HashMessage struct {
	Hash [32]byte
}

// SocketAddress : NAT Traversal
// IPv4 = 6 bytes, IPv6 = 18 bytes
type SocketAddress struct {
	IP   net.IP
	Port uint16
}

// NatTraversalMessage (Type 4 & 5)
type NatTraversalMessage struct {
	Address SocketAddress
}

// Packet : Structure globale
type Packet struct {
	Header    Header
	Body      []byte
	Signature []byte // 64 bytes si présent, nil sinon
}
