package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const HeaderSize = 7
const SignatureSize = 64

// En-tête commun de tous les messages UDP
type Header struct {
	ID     uint32
	Type   uint8
	Length uint16
}

// Encode sérialise le header en bytes
func (h *Header) Encode() []byte {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(buf[0:4], h.ID)
	buf[4] = h.Type
	binary.BigEndian.PutUint16(buf[5:7], h.Length)
	return buf
}

// DecodeHeader décode un header depuis des bytes
func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("❌ Impossible de décoder le header: données trop courtes (%d < %d)", len(data), HeaderSize)
	}
	return &Header{
		ID:     binary.BigEndian.Uint32(data[0:4]),
		Type:   data[4],
		Length: binary.BigEndian.Uint16(data[5:7]),
	}, nil
}

// HelloMessage représente un message Hello ou HelloReply
type HelloMessage struct {
	Header     Header
	Extensions uint32
	Name       string
}

// EncodeBody encode le corps du message Hello
func (m *HelloMessage) EncodeBody() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, m.Extensions)
	buf.WriteString(m.Name)
	return buf.Bytes()
}

// DecodeHelloBody décode le corps d'un message Hello
func DecodeHelloBody(data []byte) (extensions uint32, name string, err error) {
	if len(data) < 4 {
		return 0, "", fmt.Errorf("❌ Impossible de décoder le body Hello: données trop courtes (%d < 4)", len(data))
	}
	extensions = binary.BigEndian.Uint32(data[0:4])
	name = string(data[4:])
	return extensions, name, nil
}

// DatumMessage représente un message Datum
type DatumMessage struct {
	Header Header
	Hash   [32]byte
	Value  []byte
}

// EncodeBody encode le corps du message Datum
func (m *DatumMessage) EncodeBody() []byte {
	body := make([]byte, 32+len(m.Value))
	copy(body[:32], m.Hash[:])
	copy(body[32:], m.Value)
	return body
}

// DecodeDatumBody décode le corps d'un message Datum
func DecodeDatumBody(data []byte) (hash [32]byte, value []byte, err error) {
	if len(data) < 32 {
		return hash, nil, fmt.Errorf("❌ Impossible de décoder le body Datum: données trop courtes (%d < 32)", len(data))
	}
	copy(hash[:], data[:32])
	value = make([]byte, len(data)-32)
	copy(value, data[32:])
	return hash, value, nil
}

// HashMessage représente un message contenant uniquement un hash
// Utilisé pour: RootReply, DatumRequest, NoDatum
type HashMessage struct {
	Header Header
	Hash   [32]byte
}

// EncodeBody encode le corps (juste le hash)
func (m *HashMessage) EncodeBody() []byte {
	return m.Hash[:]
}

// DecodeHashBody décode un corps contenant un hash
func DecodeHashBody(data []byte) ([32]byte, error) {
	var hash [32]byte
	if len(data) < 32 {
		return hash, fmt.Errorf("❌ Impossible de décoder le body Hash: données trop courtes (%d < 32)", len(data))
	}
	copy(hash[:], data[:32])
	return hash, nil
}

// SocketAddress représente une adresse IP + port pour NAT traversal
// Format IPv4 (6 bytes): [IP: 4 bytes][Port: 2 bytes]
// Format IPv6 (18 bytes): [IP: 16 bytes][Port: 2 bytes]
type SocketAddress struct {
	IP   net.IP
	Port uint16
}

// Encode sérialise l'adresse en bytes
func (a *SocketAddress) Encode() []byte {
	ip4 := a.IP.To4()
	if ip4 != nil {
		// IPv4: 6 octets
		buf := make([]byte, 6)
		copy(buf[:4], ip4)
		binary.BigEndian.PutUint16(buf[4:6], a.Port)
		return buf
	}
	// IPv6: 18 octets
	buf := make([]byte, 18)
	copy(buf[:16], a.IP.To16())
	binary.BigEndian.PutUint16(buf[16:18], a.Port)
	return buf
}

// DecodeSocketAddress décode une adresse depuis des bytes
func DecodeSocketAddress(data []byte) (*SocketAddress, error) {
	switch len(data) {
	case 6:
		// IPv4
		return &SocketAddress{
			IP:   net.IPv4(data[0], data[1], data[2], data[3]),
			Port: binary.BigEndian.Uint16(data[4:6]),
		}, nil
	case 18:
		// IPv6
		ip := make(net.IP, 16)
		copy(ip, data[:16])
		return &SocketAddress{
			IP:   ip,
			Port: binary.BigEndian.Uint16(data[16:18]),
		}, nil
	default:
		return nil, fmt.Errorf("❌ Impossible de décoder SocketAddress: taille invalide (%d) attendue 6 ou 18", len(data))
	}
}

// ToUDPAddr convertit en *net.UDPAddr
func (a *SocketAddress) ToUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: a.IP, Port: int(a.Port)}
}

// FromUDPAddr crée un SocketAddress depuis un *net.UDPAddr
func FromUDPAddr(addr *net.UDPAddr) *SocketAddress {
	return &SocketAddress{IP: addr.IP, Port: uint16(addr.Port)}
}

// NatTraversalMessage représente un message NAT Traversal (type 4 ou 5)
type NatTraversalMessage struct {
	Header  Header
	Address SocketAddress
}

// EncodeBody encode le corps du message NAT Traversal
func (m *NatTraversalMessage) EncodeBody() []byte {
	return m.Address.Encode()
}

// ErrorMessage représente un message d'erreur
type ErrorMessage struct {
	Header  Header
	Message string
}

// EncodeBody encode le corps du message d'erreur
func (m *ErrorMessage) EncodeBody() []byte {
	return []byte(m.Message)
}

// Packet représente un paquet UDP
type Packet struct {
	Header    Header
	Body      []byte
	Signature []byte // 64 bytes si présent, nil sinon
}

// Encode sérialise le paquet
func (p *Packet) Encode() []byte {
	headerBytes := p.Header.Encode()
	result := make([]byte, len(headerBytes)+len(p.Body)+len(p.Signature))
	copy(result, headerBytes)
	copy(result[len(headerBytes):], p.Body)
	if len(p.Signature) > 0 {
		copy(result[len(headerBytes)+len(p.Body):], p.Signature)
	}
	return result
}

// DataToSign retourne les données à signer (header + body)
func (p *Packet) DataToSign() []byte {
	headerBytes := p.Header.Encode()
	result := make([]byte, len(headerBytes)+len(p.Body))
	copy(result, headerBytes)
	copy(result[len(headerBytes):], p.Body)
	return result
}

// DecodePacket décode un paquet depuis des bytes
func DecodePacket(data []byte) (*Packet, error) {
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	bodyEnd := HeaderSize + int(header.Length)
	if len(data) < bodyEnd {
		return nil, fmt.Errorf("❌ Impossible de décoder le paquet: données trop courtes (%d < %d)", len(data), bodyEnd)
	}
	packet := &Packet{
		Header: *header,
		Body:   data[HeaderSize:bodyEnd],
	}
	// Vérifier s'il y a une signature
	if len(data) >= bodyEnd+SignatureSize {
		packet.Signature = data[bodyEnd : bodyEnd+SignatureSize]
	}
	return packet, nil
}
