package transport

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"main/internal/config"
	"main/internal/crypto"
	"main/internal/protocol"
	"net/http"
	"strings"
	"time"
)

// Client global avec un timeout pour ne pas freezer l'app si l'annuaire est down
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

// GetListPeers récupère la liste des noms enregistrés
func GetListPeers() ([]string, error) {
	resp, err := httpClient.Get(protocol.GetURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parsing simple : une ligne = un peer
	lines := strings.Split(string(body), "\n")
	var peers []string

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			peers = append(peers, l)
		}
	}
	return peers, nil
}

// GetAddr récupère la string des adresses d'un peer
func GetAddr(name string) (string, error) {
	// Construction d'URL
	url := protocol.GetURL() + name + "/addresses"

	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetKey récupère la clé publique brute (64 bytes)
func GetKey(name string) ([]byte, error) {
	url := protocol.GetURL() + name + "/key"

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("peer not found")
	}

	return io.ReadAll(resp.Body)
}

// RegisterHTTP publie notre clé publique sur l'annuaire
func RegisterHTTP(privKey *ecdsa.PrivateKey) error {
	// 1. Préparation des données
	pubKey := crypto.ExtractPublicKey(privKey)
	keyBytes := crypto.PublicKeyToBytes(pubKey)

	// 2. Création requête
	myName := config.GlobalConfig.Peer.Name
	url := protocol.GetURL() + myName + "/key"
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(keyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// 3. Envoi
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 200 OK ou 204 No Content sont acceptés
	if resp.StatusCode >= 300 {
		return fmt.Errorf("registration failed: %s", resp.Status)
	}

	return nil
}
