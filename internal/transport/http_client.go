package transport

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"io"
	"main/internal/crypto"
	"main/internal/protocol"
	"net"
	"net/http"
	"strings"
	"time"
)

// FetchPeerList récupère la liste de tous les peers enregistrés sur le serveur
func FetchPeerList() ([]string, error) {
	resp, err := http.Get(protocol.URL)
	if err != nil {
		return nil, fmt.Errorf("échec récupération liste peers: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("échec lecture réponse: %w", err)
	}

	lines := strings.Split(string(responseBody), "\n")
	var peerNames []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			peerNames = append(peerNames, trimmedLine)
		}
	}
	return peerNames, nil
}

// GetListPeers est un alias pour FetchPeerList (compatibilité)
func GetListPeers() ([]string, error) {
	return FetchPeerList()
}

// FetchPeerAddresses récupère les adresses UDP d'un peer par son nom
func FetchPeerAddresses(peerName string) (string, error) {
	resp, err := http.Get(protocol.URL + peerName + "/addresses")
	if err != nil {
		return "", fmt.Errorf("échec récupération adresses: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("échec lecture réponse: %w", err)
	}
	return string(responseBody), nil
}

// GetAddr est un alias pour FetchPeerAddresses (compatibilité)
func GetAddr(peerName string) (string, error) {
	return FetchPeerAddresses(peerName)
}

// FetchPeerPublicKey récupère la clé publique d'un peer par son nom
func FetchPeerPublicKey(peerName string) ([]byte, error) {
	resp, err := http.Get(protocol.URL + peerName + "/key")
	if err != nil {
		return nil, fmt.Errorf("échec récupération clé publique: %w", err)
	}
	defer resp.Body.Close()

	publicKeyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("échec lecture réponse: %w", err)
	}
	return publicKeyBytes, nil
}

// GetKey est un alias pour FetchPeerPublicKey (compatibilité)
func GetKey(peerName string) ([]byte, error) {
	return FetchPeerPublicKey(peerName)
}

// RegisterPublicKey enregistre notre clé publique sur le serveur HTTP
func RegisterPublicKey(privateKey *ecdsa.PrivateKey) error {
	publicKey := crypto.ExtractPublicKey(privateKey)
	publicKeyBytes := crypto.PublicKeyToBytes(publicKey)

	registrationURL := protocol.URL + protocol.MyName + "/key"
	request, err := http.NewRequest(http.MethodPut, registrationURL, bytes.NewReader(publicKeyBytes))
	if err != nil {
		return fmt.Errorf("échec création requête: %w", err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")

	httpClient := &http.Client{Timeout: 5 * time.Second}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("échec envoi requête: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 && response.StatusCode != 204 {
		return fmt.Errorf("erreur serveur HTTP: %s", response.Status)
	}

	return nil
}

// RegisterHTTP est un alias pour RegisterPublicKey (compatibilité)
func RegisterHTTP(privateKey *ecdsa.PrivateKey) error {
	return RegisterPublicKey(privateKey)
}

// buildPacket construit un paquet UDP avec header + body + signature optionnelle
func buildPacket(id uint32, msgType uint8, body []byte, privKey *ecdsa.PrivateKey) []byte {
	headerBuf := new(bytes.Buffer)
	binary.Write(headerBuf, binary.BigEndian, id)
	binary.Write(headerBuf, binary.BigEndian, msgType)
	binary.Write(headerBuf, binary.BigEndian, uint16(len(body)))

	dataToSign := append(headerBuf.Bytes(), body...)

	if privKey != nil {
		signature := crypto.ComputeSignature(privKey, dataToSign)
		return append(dataToSign, signature...)
	}
	return dataToSign
}

// SendHello envoie un message Hello (doit être signé)
func SendHello(conn *net.UDPConn, destAddr *net.UDPAddr, myName string, privKey *ecdsa.PrivateKey) (uint32, error) {
	bodyBuf := new(bytes.Buffer)
	extensions := uint32(0) // Pas d'extensions pour l'instant
	binary.Write(bodyBuf, binary.BigEndian, extensions)
	bodyBuf.Write([]byte(myName))

	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.Hello, bodyBuf.Bytes(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi Hello: %w", err)
	}

	return id, nil
}

// SendHelloReply envoie une réponse HelloReply (doit être signé)
func SendHelloReply(conn *net.UDPConn, destAddr *net.UDPAddr, myName string, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	bodyBuf := new(bytes.Buffer)
	extensions := uint32(0)
	binary.Write(bodyBuf, binary.BigEndian, extensions)
	bodyBuf.Write([]byte(myName))

	packet := buildPacket(replyToID, protocol.HelloReply, bodyBuf.Bytes(), privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi HelloReply: %w", err)
	}

	return nil
}

// SendPing envoie un message Ping (pas besoin de signature)
func SendPing(conn *net.UDPConn, destAddr *net.UDPAddr) (uint32, error) {
	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.Ping, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi Ping: %w", err)
	}

	return id, nil
}

// SendOk envoie une réponse Ok (pas besoin de signature)
func SendOk(conn *net.UDPConn, destAddr *net.UDPAddr, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.Ok, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi Ok: %w", err)
	}

	return nil
}

// SendRootRequest demande le hash racine d'un peer
func SendRootRequest(conn *net.UDPConn, destAddr *net.UDPAddr) (uint32, error) {
	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.RootRequest, []byte{}, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi RootRequest: %w", err)
	}

	return id, nil
}

// SendRootReply envoie le hash racine (doit être signé)
func SendRootReply(conn *net.UDPConn, destAddr *net.UDPAddr, rootHash [32]byte, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.RootReply, rootHash[:], privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi RootReply: %w", err)
	}

	return nil
}

// SendDatumRequest demande un datum par son hash
func SendDatumRequest(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte) (uint32, error) {
	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.DatumRequest, hash[:], nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi DatumRequest: %w", err)
	}

	return id, nil
}

// SendDatum envoie un datum (pas besoin de signature - protégé par Merkle)
func SendDatum(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte, value []byte, replyToID uint32) error {
	body := make([]byte, 32+len(value))
	copy(body[:32], hash[:])
	copy(body[32:], value)

	packet := buildPacket(replyToID, protocol.Datum, body, nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi Datum: %w", err)
	}

	return nil
}

// SendNoDatum signale qu'on n'a pas le datum demandé (doit être signé)
func SendNoDatum(conn *net.UDPConn, destAddr *net.UDPAddr, hash [32]byte, privKey *ecdsa.PrivateKey, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.NoDatum, hash[:], privKey)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi NoDatum: %w", err)
	}

	return nil
}

// SendError envoie un message d'erreur
func SendError(conn *net.UDPConn, destAddr *net.UDPAddr, errorMsg string, replyToID uint32) error {
	packet := buildPacket(replyToID, protocol.Error, []byte(errorMsg), nil)

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi Error: %w", err)
	}

	return nil
}

// SendNatTraversalRequest envoie une demande de NAT traversal à un intermédiaire (doit être signé)
func SendNatTraversalRequest(conn *net.UDPConn, relayAddr *net.UDPAddr, targetAddr *net.UDPAddr, privKey *ecdsa.PrivateKey) (uint32, error) {
	body := encodeSocketAddr(targetAddr)

	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.NatTraversalRequest, body, privKey)

	_, err := conn.WriteToUDP(packet, relayAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi NatTraversalRequest: %w", err)
	}

	return id, nil
}

// SendNatTraversalRequest2 envoie une demande relay au peer cible (doit être signé)
func SendNatTraversalRequest2(conn *net.UDPConn, targetAddr *net.UDPAddr, requesterAddr *net.UDPAddr, privKey *ecdsa.PrivateKey) (uint32, error) {
	body := encodeSocketAddr(requesterAddr)

	id := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	packet := buildPacket(id, protocol.NatTraversalRequest2, body, privKey)

	_, err := conn.WriteToUDP(packet, targetAddr)
	if err != nil {
		return 0, fmt.Errorf("erreur envoi NatTraversalRequest2: %w", err)
	}

	return id, nil
}

// encodeSocketAddr encode une adresse UDP selon le format spécifié dans 4.1.6
//
// Format IPv4 (6 octets):
//
//	[0-3]  : Adresse IPv4 (4 octets, big-endian)
//	[4-5]  : Port (2 octets, big-endian)
//
// Format IPv6 (18 octets):
//
//	[0-15] : Adresse IPv6 (16 octets)
//	[16-17]: Port (2 octets, big-endian)
//
// Le récepteur détermine le type d'adresse par la longueur du body:
// - len(body) == 6  → IPv4
// - len(body) == 18 → IPv6
func encodeSocketAddr(addr *net.UDPAddr) []byte {
	ip := addr.IP.To4()
	if ip != nil {
		// IPv4: 4 bytes IP + 2 bytes port = 6 octets
		body := make([]byte, 6)
		copy(body[:4], ip)
		binary.BigEndian.PutUint16(body[4:6], uint16(addr.Port))
		return body
	}
	// IPv6: 16 bytes IP + 2 bytes port = 18 octets
	body := make([]byte, 18)
	copy(body[:16], addr.IP.To16())
	binary.BigEndian.PutUint16(body[16:18], uint16(addr.Port))
	return body
}
