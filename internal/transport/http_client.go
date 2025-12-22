package transport

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"main/internal/crypto"
	"net/http"
	"strings"
	"time"
)

const (
	URL       = "https://jch.irif.fr:8443/peers/"
	ServerUDP = "[2001:660:3301:9243::51c2:1ee5]:8443" // Adresse UDP du serveur
	MyName    = "Gui"                                  // Votre nom de pair
)

func GetListPeers() ([]string, error) {
	resp, err := http.Get(URL)
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

func GetAddr(name string) (string, error) {
	resp, err := http.Get(URL + name + "/addresses")
	if err != nil {
		return "", fmt.Errorf("failed to get address: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	return string(body), nil
}

func GetKey(name string) ([]byte, error) {
	resp, err := http.Get(URL + name + "/key")
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

	url := fmt.Sprintf(URL + MyName + "/key")
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
