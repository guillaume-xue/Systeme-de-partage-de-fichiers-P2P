package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

/*
Structures et fonctions de gestion de la configuration du programme
*/
type Config struct {
	Peer    PeerConfig    `json:"peer"`
	Server  ServerConfig  `json:"server"`
	Network NetworkConfig `json:"network"`
	Merkle  MerkleConfig  `json:"merkle"`
	NAT     NATConfig     `json:"nat"`
}

type PeerConfig struct {
	Name             string        `json:"name"`
	KeyFile          string        `json:"keyfile"`
	SharedDir        string        `json:"shared_dir"`
	ExpiryTimeoutMin int           `json:"expiry_timeout_minutes"`
	ExpiryTimeout    time.Duration `json:"-"`
}

type ServerConfig struct {
	URL         string `json:"url"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
}

type NetworkConfig struct {
	Timeout                time.Duration `json:"-"`
	TimeoutSeconds         int           `json:"timeout_seconds"`
	KeepAlive              time.Duration `json:"-"`
	KeepAliveSeconds       int           `json:"keepalive_seconds"`
	MaxWindowSize          int           `json:"max_window_size"`
	InitialWindow          int           `json:"initial_window"`
	MinWindowSize          int           `json:"min_window_size"`
	TimeoutDownload        time.Duration `json:"-"`
	TimeoutSecondsDownload int           `json:"timeout_seconds_download"`
	ProcessorWorkers       int           `json:"processor_workers"`

	// Serveur UDP
	MaxPacketWorkers        int `json:"max_packet_workers"`
	UDPReadBufferSize       int `json:"udp_read_buffer_size"`
	WorkerOverflowTimeoutMs int `json:"worker_overflow_timeout_ms"`
	FetchMaxRetries         int `json:"fetch_max_retries"`

	// Handshake
	HandshakeTimeoutSeconds int           `json:"handshake_timeout_seconds"`
	HandshakeTimeout        time.Duration `json:"-"`
	HandshakeBufferSize     int           `json:"handshake_buffer_size"`

	// Flow control
	MinRTOMs int           `json:"min_rto_ms"`
	MinRTO   time.Duration `json:"-"`

	// Downloader
	SenderWaitMs             int `json:"sender_wait_ms"`
	MonitorIntervalMs        int `json:"monitor_interval_ms"`
	CompletionConfirmDelayMs int `json:"completion_confirm_delay_ms"`
	MaxRetries               int `json:"download_max_retries"`
	MaxQueueSize             int `json:"max_queue_size"`

	// Disk Downloader
	DiskSenderTickMs             int `json:"disk_sender_tick_ms"`
	DiskMonitorIntervalMs        int `json:"disk_monitor_interval_ms"`
	DiskCompletionConfirmDelayMs int `json:"disk_completion_confirm_delay_ms"`

	// HTTP
	HTTPClientTimeoutSeconds int           `json:"http_client_timeout_seconds"`
	HTTPClientTimeout        time.Duration `json:"-"`

	// Divers
	DownloadTimeoutMinutes     int           `json:"download_timeout_minutes"`
	DownloadTimeout            time.Duration `json:"-"`
	ResolveDatumTimeoutSeconds int           `json:"resolve_datum_timeout_seconds"`
	ResolveDatumTimeout        time.Duration `json:"-"`
	RootReplyTimeoutSeconds    int           `json:"root_reply_timeout_seconds"`
	RootReplyTimeout           time.Duration `json:"-"`
	StartupDelayMs             int           `json:"startup_delay_ms"`
	DirectConnectDelayMs       int           `json:"direct_connect_delay_ms"`
}

type MerkleConfig struct {
	MaxChunkSize         int           `json:"max_chunk_size"`
	MaxDirEntries        int           `json:"max_dir_entries"`
	MaxBigChildren       int           `json:"max_big_children"`
	WatchIntervalSeconds int           `json:"watch_interval_seconds"`
	WatchInterval        time.Duration `json:"-"`
}

type NATConfig struct {
	ResponseChannelSize     int    `json:"response_channel_size"`
	PingCount               int    `json:"ping_count"`
	InitialPingDelaySeconds int    `json:"initial_ping_delay_seconds"`
	FinalTimeoutMs          int    `json:"final_timeout_ms"`
	DefaultRelayPeer        string `json:"default_relay_peer"`
	PingSpamCount           int    `json:"ping_spam_count"`
	PingSpamFinalTimeoutMs  int    `json:"ping_spam_final_timeout_ms"`
	MenuResponseChannelSize int    `json:"menu_response_channel_size"`
}

var GlobalConfig *Config

// Chargement de la configuration
func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Erreur de la lecture du fichier config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("Erreur dans le parsing de la config: %w", err)
	}

	cfg.computeDurations()

	GlobalConfig = &cfg
	return VerifConfig(GlobalConfig)
}

// computeDurations convertit les valeurs entières de config en time.Duration
func (cfg *Config) computeDurations() {
	cfg.Network.Timeout = time.Duration(cfg.Network.TimeoutSeconds) * time.Second
	cfg.Network.KeepAlive = time.Duration(cfg.Network.KeepAliveSeconds) * time.Second
	cfg.Network.TimeoutDownload = time.Duration(cfg.Network.TimeoutSecondsDownload) * time.Second
	cfg.Network.HandshakeTimeout = time.Duration(cfg.Network.HandshakeTimeoutSeconds) * time.Second
	cfg.Network.MinRTO = time.Duration(cfg.Network.MinRTOMs) * time.Millisecond
	cfg.Network.HTTPClientTimeout = time.Duration(cfg.Network.HTTPClientTimeoutSeconds) * time.Second
	cfg.Network.DownloadTimeout = time.Duration(cfg.Network.DownloadTimeoutMinutes) * time.Minute
	cfg.Network.ResolveDatumTimeout = time.Duration(cfg.Network.ResolveDatumTimeoutSeconds) * time.Second
	cfg.Network.RootReplyTimeout = time.Duration(cfg.Network.RootReplyTimeoutSeconds) * time.Second
	cfg.Peer.ExpiryTimeout = time.Duration(cfg.Peer.ExpiryTimeoutMin) * time.Minute
	cfg.Merkle.WatchInterval = time.Duration(cfg.Merkle.WatchIntervalSeconds) * time.Second
}

// Charge la config sinon utilise les valeurs par défaut
func LoadOrDefault(path string) *Config {
	if err := Load(path); err != nil {
		fmt.Printf("⚠️ Impossible de charger %s: %v\n", path, err)
		fmt.Println("ℹ️️\tUtilisation de la configuration par défaut")
		GlobalConfig = DefaultConfig()
	}
	return GlobalConfig
}

// Config par défaut
func DefaultConfig() *Config {
	cfg := &Config{
		Peer: PeerConfig{
			Name:             "heee1",
			KeyFile:          "client_key.pem",
			SharedDir:        "shared",
			ExpiryTimeoutMin: 5,
		},
		Server: ServerConfig{
			URL:         "https://jch.irif.fr:8443/peers/",
			IPv4Address: "81.194.30.229:8443",
			IPv6Address: "[2001:660:3301:9243::51c2:1ee5]:8443",
		},
		Network: NetworkConfig{
			TimeoutSeconds:         3,
			KeepAliveSeconds:       120,
			MaxWindowSize:          256,
			InitialWindow:          10,
			MinWindowSize:          2,
			TimeoutSecondsDownload: 3,
			ProcessorWorkers:       20,

			MaxPacketWorkers:        100,
			UDPReadBufferSize:       65535,
			WorkerOverflowTimeoutMs: 100,
			FetchMaxRetries:         3,

			HandshakeTimeoutSeconds: 2,
			HandshakeBufferSize:     2048,

			MinRTOMs: 50,

			SenderWaitMs:             10,
			MonitorIntervalMs:        200,
			CompletionConfirmDelayMs: 100,
			MaxRetries:               3,
			MaxQueueSize:             1024,

			DiskSenderTickMs:             5,
			DiskMonitorIntervalMs:        500,
			DiskCompletionConfirmDelayMs: 200,

			HTTPClientTimeoutSeconds: 5,

			DownloadTimeoutMinutes:     5,
			ResolveDatumTimeoutSeconds: 3,
			RootReplyTimeoutSeconds:    3,
			StartupDelayMs:             1000,
			DirectConnectDelayMs:       500,
		},
		Merkle: MerkleConfig{
			MaxChunkSize:         1024,
			MaxDirEntries:        16,
			MaxBigChildren:       32,
			WatchIntervalSeconds: 5,
		},
		NAT: NATConfig{
			ResponseChannelSize:     10,
			PingCount:               3,
			InitialPingDelaySeconds: 1,
			FinalTimeoutMs:          500,
			DefaultRelayPeer:        "jch.irif.fr",
			PingSpamCount:           3,
			PingSpamFinalTimeoutMs:  500,
			MenuResponseChannelSize: 10,
		},
	}
	cfg.computeDurations()
	return cfg
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
	if cfg.Network.TimeoutSeconds <= 0 {
		return fmt.Errorf("network timeout must be positive")
	}
	if cfg.Network.KeepAliveSeconds <= 0 {
		return fmt.Errorf("network keepalive must be positive")
	}
	if cfg.Network.MaxWindowSize <= 0 {
		return fmt.Errorf("network max window size must be positive")
	}
	if cfg.Network.InitialWindow <= 0 {
		return fmt.Errorf("network initial window size must be positive")
	}
	if cfg.Network.MinWindowSize <= 0 {
		return fmt.Errorf("network min window size must be positive")
	}
	if cfg.Network.TimeoutSecondsDownload <= 0 {
		return fmt.Errorf("network download timeout must be positive")
	}
	if cfg.Merkle.MaxChunkSize <= 0 {
		return fmt.Errorf("merkle max chunk size must be positive")
	}
	if cfg.Merkle.MaxDirEntries <= 0 {
		return fmt.Errorf("merkle max dir entries must be positive")
	}
	if cfg.Merkle.MaxBigChildren <= 0 {
		return fmt.Errorf("merkle max big children must be positive")
	}
	return nil
}
