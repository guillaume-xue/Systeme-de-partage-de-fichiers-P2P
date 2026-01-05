package transport

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"main/internal/crypto"
	"main/internal/protocol"
	"net"
	"net/http"
	"strings"
	"time"
)

func GetListPeers() ([]string, error) {
	resp, err := http.Get(protocol.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to get peers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	lines := strings.Split(string(body), "\n")
	var peers []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			peers = append(peers, line)
		}
	}
	return peers, nil
}

func GetAddr(name string) ([]byte, error) {
	resp, err := http.Get(protocol.URL + name + "/addresses")
	if err != nil {
		return nil, fmt.Errorf("failed to get address: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

func GetKey(name string) ([]byte, error) {
	resp, err := http.Get(protocol.URL + name + "/key")
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

func RegisterHTTP(privateKey *ecdsa.PrivateKey) error {
	pubKey := crypto.ExtractPublicKey(privateKey)
	pubBytes := crypto.PublicKeyToBytes(pubKey)

	url := fmt.Sprintf(protocol.URL + protocol.MyName + "/key")
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(pubBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("erreur serveur HTTP: %s", resp.Status)
	}

	return nil
}

func SendPacket(conn *net.UDPConn, destAddr *net.UDPAddr, msgID uint32, msgType uint8, data []byte) error {

	var packet []byte

	switch msgType {
	case protocol.Ping:
		packet = protocol.EncodeMessages(msgID, protocol.Ping, []byte{})
	case protocol.Ok:
		packet = protocol.EncodeMessages(msgID, protocol.Ok, []byte{})
	case protocol.Hello:
		myName := protocol.MyName
		packet = protocol.EncodeHandshakeMessage(msgID, protocol.Hello, 0, []byte(myName))
	case protocol.HelloReply:
		myName := protocol.MyName
		packet = protocol.EncodeHandshakeMessage(msgID, protocol.HelloReply, 0, []byte(myName))
	case protocol.RootRequest:
		packet = protocol.EncodeRootAndData(msgID, protocol.RootRequest, []byte{})
	case protocol.RootReply:
		packet = protocol.EncodeRootAndData(msgID, protocol.RootReply, []byte{})
	case protocol.DatumRequest:
		packet = protocol.EncodeRootAndData(msgID, protocol.DatumRequest, data)
	default:
		return fmt.Errorf("type de message inconnu: %d", msgType)
	}

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi Message: %w", err)
	}

	fmt.Printf("Message type %d envoyé à %s (ID:%d)\n", msgType, destAddr, msgID)
	return nil
}

func RegisterClient(conn4 *net.UDPConn, conn6 *net.UDPConn) {
	privKey, _ := crypto.LoadOrGenerateKey(protocol.FILENAME)

	fmt.Println("Port UDP 8080 ouvert pour écoute et envoi.")

	if err := RegisterHTTP(privKey); err != nil {
		fmt.Println("Erreur HTTP:", err)
	}

	serverAddr6, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP6)
	serverAddr4, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP4)

	if err := SendPacket(conn6, serverAddr6, uint32(time.Now().Unix()), protocol.Hello, []byte{}); err != nil {
		fmt.Println("Erreur envoi Hello:", err)
	}
	if err := SendPacket(conn4, serverAddr4, uint32(time.Now().Unix()), protocol.Hello, []byte{}); err != nil {
		fmt.Println("Erreur envoi Hello:", err)
	}
}
