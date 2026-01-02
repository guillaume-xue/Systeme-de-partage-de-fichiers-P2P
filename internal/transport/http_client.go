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

func SendHandshake(conn *net.UDPConn, destAddr *net.UDPAddr, msgID uint32, msgType uint8) error {
	myName := protocol.MyName

	packet := protocol.EncodeHandshakeMessage(msgID, msgType, 0, []byte(myName))

	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi Message: %w", err)
	}

	fmt.Printf("Message envoyé à %s (ID:%d)\n", destAddr, msgID)
	return nil
}

func SendPing(conn *net.UDPConn, destAddr *net.UDPAddr, msgID uint32) error {
	packet := protocol.EncodeMessages(msgID, protocol.Ping, []byte{})
	_, err := conn.WriteToUDP(packet, destAddr)
	if err != nil {
		return fmt.Errorf("erreur envoi ping: %w", err)
	}
	fmt.Printf("Ping envoyé à %s (ID:%d)\n", destAddr, msgID)
	return nil
}

func RegisterClient() {
	privKey, _ := crypto.LoadOrGenerateKey(protocol.FILENAME)

	localAddr, _ := net.ResolveUDPAddr("udp", ":8080")

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Port UDP 8080 ouvert pour écoute et envoi.")

	go ListenLoop(conn)

	if err := RegisterHTTP(privKey); err != nil {
		fmt.Println("Erreur HTTP:", err)
	}

	serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP)
	if err := SendHandshake(conn, serverAddr, uint32(time.Now().Unix()), protocol.Hello); err != nil {
		fmt.Println("Erreur envoi Hello:", err)
	}

	select {}
}
