package transport

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"main/internal/crypto"
	"main/internal/protocol"
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

// GetListPeers est un alias pour FetchPeerList
func GetListPeers() ([]string, error) {
	return FetchPeerList()
}

// GetAddr est un alias pour FetchPeerAddresses
func GetAddr(peerName string) (string, error) {
	return FetchPeerAddresses(peerName)
}

// GetKey est un alias pour FetchPeerPublicKey
func GetKey(peerName string) ([]byte, error) {
	return FetchPeerPublicKey(peerName)
}

// RegisterHTTP est un alias pour RegisterPublicKey
func RegisterHTTP(privateKey *ecdsa.PrivateKey) error {
	return RegisterPublicKey(privateKey)
}
