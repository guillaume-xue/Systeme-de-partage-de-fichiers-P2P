package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Configuration json
type Config struct {
	Peer    PeerConfig    `json:"peer"`
	Server  ServerConfig  `json:"server"`
	Network NetworkConfig `json:"network"`
	Merkle  MerkleConfig  `json:"merkle"`
}

type PeerConfig struct {
	Name    string `json:"name"`
	KeyFile string `json:"keyfile"`
}

type ServerConfig struct {
	URL         string `json:"url"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
}

type NetworkConfig struct {
	Timeout                time.Duration `json:"-"` // Géré via TimeoutSeconds
	TimeoutSeconds         int           `json:"timeout_seconds"`
	KeepAlive              time.Duration `json:"-"` // Géré via KeepAliveSeconds
	KeepAliveSeconds       int           `json:"keepalive_seconds"`
	MaxWindowSize          int           `json:"max_window_size"`
	InitialWindow          int           `json:"initial_window"`
	MinWindowSize          int           `json:"min_window_size"`
	TimeoutDownload        time.Duration `json:"-"` // Géré via TimeoutSecondsDownload
	TimeoutSecondsDownload int           `json:"timeout_seconds_download"`
}

type MerkleConfig struct {
	MaxChunkSize   int `json:"max_chunk_size"`
	MaxDirEntries  int `json:"max_dir_entries"`
	MaxBigChildren int `json:"max_big_children"`
}

var GlobalConfig *Config

// Chargement de la configuration
func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("lecture config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing config JSON: %w", err)
	}

	// Conversion des durées
	cfg.Network.Timeout = time.Duration(cfg.Network.TimeoutSeconds) * time.Second
	cfg.Network.KeepAlive = time.Duration(cfg.Network.KeepAliveSeconds) * time.Second
	cfg.Network.TimeoutDownload = time.Duration(cfg.Network.TimeoutSecondsDownload) * time.Second

	GlobalConfig = &cfg
	return VerifConfig(GlobalConfig)
}

// Charge la config sinon utilise les valeurs par défaut
func LoadOrDefault(path string) *Config {
	if err := Load(path); err != nil {
		fmt.Printf("⚠️ Impossible de charger %s: %v\n", path, err)
		fmt.Println("📋	Utilisation de la configuration par défaut")
		GlobalConfig = DefaultConfig()
	}
	return GlobalConfig
}

// Config par défaut
func DefaultConfig() *Config {
	return &Config{
		Peer: PeerConfig{
			Name:    "heee1",
			KeyFile: "client_key.pem",
		},
		Server: ServerConfig{
			URL:         "https://jch.irif.fr:8443/peers/",
			IPv4Address: "81.194.30.229:8443",
			IPv6Address: "[2001:660:3301:9243::51c2:1ee5]:8443",
		},
		Network: NetworkConfig{
			TimeoutSeconds:         3,
			Timeout:                3 * time.Second,
			KeepAliveSeconds:       135,
			KeepAlive:              135 * time.Second,
			MaxWindowSize:          64,
			InitialWindow:          4,
			MinWindowSize:          1,
			TimeoutSecondsDownload: 2,
			TimeoutDownload:        2 * time.Second,
		},
		Merkle: MerkleConfig{
			MaxChunkSize:   1024,
			MaxDirEntries:  16,
			MaxBigChildren: 32,
		},
	}
}

func VerifConfig(cfg *Config) error {
	if cfg.Peer.Name == "" {
		return fmt.Errorf("peer name is empty")
	}
	if cfg.Peer.KeyFile == "" {
		return fmt.Errorf("peer keyfile is empty")
	}
	if cfg.Server.URL == "" {
		return fmt.Errorf("server URL is empty")
	}
	if cfg.Server.IPv4Address == "" {
		return fmt.Errorf("server IPv4 address is empty")
	}
	if cfg.Server.IPv6Address == "" {
		return fmt.Errorf("server IPv6 address is empty")
	}
	if cfg.Network.TimeoutSeconds < 0 {
		return fmt.Errorf("network timeout must be positive")
	}
	if cfg.Network.KeepAliveSeconds < 0 {
		return fmt.Errorf("network keepalive must be positive")
	}
	if cfg.Network.MaxWindowSize < 0 {
		return fmt.Errorf("network max window size must be positive")
	}
	if cfg.Network.InitialWindow < 0 {
		return fmt.Errorf("network initial window size must be positive")
	}
	if cfg.Network.MinWindowSize < 0 {
		return fmt.Errorf("network min window size must be positive")
	}
	if cfg.Network.TimeoutSecondsDownload < 0 {
		return fmt.Errorf("network download timeout must be positive")
	}
	if cfg.Merkle.MaxChunkSize < 0 {
		return fmt.Errorf("merkle max chunk size must be positive")
	}
	if cfg.Merkle.MaxDirEntries < 0 {
		return fmt.Errorf("merkle max dir entries must be positive")
	}
	if cfg.Merkle.MaxBigChildren < 0 {
		return fmt.Errorf("merkle max big children must be positive")
	}
	return nil
}
