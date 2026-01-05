package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func (h *Header) Encode() []byte {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(buf[0:4], h.ID)
	buf[4] = h.Type
	binary.BigEndian.PutUint16(buf[5:7], h.Length)
	return buf
}

func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("❌ Impossible de décoder le head: données trop courtes (%d < %d)", len(data), HeaderSize)
	}
	return &Header{
		ID:     binary.BigEndian.Uint32(data[0:4]),
		Type:   data[4],
		Length: binary.BigEndian.Uint16(data[5:7]),
	}, nil
}

// HelloMessage (Type 1 & 130)
type HelloMessage struct {
	Extensions uint32
	Name       string
}

func (m *HelloMessage) EncodeBody() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, m.Extensions)
	buf.WriteString(m.Name)
	return buf.Bytes()
}

func DecodeHelloBody(data []byte) (uint32, string, error) {
	if len(data) < 4 {
		return 0, "", fmt.Errorf("❌ Impossible de décoder le body Hello: données trop courtes (%d < 4)", len(data))
	}
	ext := binary.BigEndian.Uint32(data[0:4])
	name := string(data[4:])
	return ext, name, nil
}

// DatumMessage (Type 132) : [Hash:32][Value...]
type DatumMessage struct {
	Hash  [32]byte
	Value []byte
}

func (m *DatumMessage) EncodeBody() []byte {
	body := make([]byte, 32+len(m.Value))
	copy(body[:32], m.Hash[:])
	copy(body[32:], m.Value)
	return body
}

func DecodeDatumBody(data []byte) ([32]byte, []byte, error) {
	var hash [32]byte
	if len(data) < 32 {
		return hash, nil, fmt.Errorf("❌ Impossible de décoder le body Datum: données trop courtes (%d < 32)", len(data))
	}
	copy(hash[:], data[:32])
	value := make([]byte, len(data)-32)
	copy(value, data[32:])
	return hash, value, nil
}

// HashMessage (Type 2, 3, 131, 133) : [Hash:32]
type HashMessage struct {
	Hash [32]byte
}

func (m *HashMessage) EncodeBody() []byte {
	return m.Hash[:]
}

func DecodeHashBody(data []byte) ([32]byte, error) {
	var hash [32]byte
	if len(data) < 32 {
		return hash, fmt.Errorf("❌ Impossible de décoder le body Hash: données trop courtes (%d < 32)", len(data))
	}
	copy(hash[:], data[:32])
	return hash, nil
}

// SocketAddress : NAT Traversal
// IPv4 = 6 bytes, IPv6 = 18 bytes
type SocketAddress struct {
	IP   net.IP
	Port uint16
}

func (a *SocketAddress) Encode() []byte {
	ip4 := a.IP.To4()
	if ip4 != nil {
		buf := make([]byte, 6)
		copy(buf[:4], ip4)
		binary.BigEndian.PutUint16(buf[4:6], a.Port)
		return buf
	}
	buf := make([]byte, 18)
	copy(buf[:16], a.IP.To16())
	binary.BigEndian.PutUint16(buf[16:18], a.Port)
	return buf
}

func DecodeSocketAddress(data []byte) (*SocketAddress, error) {
	switch len(data) {
	case 6:
		return &SocketAddress{
			IP:   net.IP(data[:4]),
			Port: binary.BigEndian.Uint16(data[4:6]),
		}, nil
	case 18:
		ip := make(net.IP, 16)
		copy(ip, data[:16])
		return &SocketAddress{
			IP:   net.IP(data[:16]),
			Port: binary.BigEndian.Uint16(data[16:18]),
		}, nil
	default:
		return nil, fmt.Errorf("❌ Impossible de décoder SocketAddress: taille invalide (%d) attendue 6 ou 18", len(data))
	}
}

// Conversion helpers
func (a *SocketAddress) ToUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: a.IP, Port: int(a.Port)}
}

func FromUDPAddr(addr *net.UDPAddr) *SocketAddress {
	return &SocketAddress{IP: addr.IP, Port: uint16(addr.Port)}
}

// NatTraversalMessage (Type 4 & 5)
type NatTraversalMessage struct {
	Address SocketAddress
}

func (m *NatTraversalMessage) EncodeBody() []byte {
	return m.Address.Encode()
}

// Packet : Structure globale
type Packet struct {
	Header    Header
	Body      []byte
	Signature []byte // 64 bytes si présent, nil sinon
}

// Encode sconstruit le paquete final pour le réseau
func (p *Packet) Encode() []byte {
	head := p.Header.Encode()
	buf := make([]byte, len(head)+len(p.Body)+len(p.Signature))
	copy(buf[0:], head)
	copy(buf[HeaderSize:], p.Body)
	if len(p.Signature) > 0 {
		copy(buf[HeaderSize+len(p.Body):], p.Signature)
	}
	return buf
}

// DataToSign retourne les données à signer (header + body)
func (p *Packet) DataToSign() []byte {
	head := p.Header.Encode()
	buf := make([]byte, len(head)+len(p.Body))
	copy(buf, head)
	copy(buf[len(head):], p.Body)
	return buf
}

// DecodePacket décode un paquet depuis des bytes
func DecodePacket(data []byte) (*Packet, error) {
	head, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	bodyStart := HeaderSize
	bodyEnd := HeaderSize + int(head.Length)
	if len(data) < bodyEnd {
		return nil, fmt.Errorf("❌ Impossible de décoder le paquet: données trop courtes (%d < %d)", len(data), bodyEnd)
	}
	packet := &Packet{
		Header: *head,
		Body:   data[bodyStart:bodyEnd],
	}
	// Vérifier s'il y a une signature
	if len(data) >= bodyEnd+SignatureSize {
		packet.Signature = data[bodyEnd : bodyEnd+SignatureSize]
	}
	return packet, nil
}
