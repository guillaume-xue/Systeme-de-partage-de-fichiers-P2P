package transport

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

const URL = "https://jch.irif.fr:8443/peers/"

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

func GetKey(name string) (string, error) {
	resp, err := http.Get(URL + name + "/key")
	if err != nil {
		return "", fmt.Errorf("failed to get key: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	return string(body), nil
}
