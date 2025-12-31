package transport

import (
	"crypto/ecdsa"
	"fmt"
	"main/internal/protocol"
	"net"
	"runtime"
	"sync"
	"time"
)

// NetworkConfig contient la configuration réseau active
type NetworkConfig struct {
	ServerAddr   *net.UDPAddr
	DualStack    bool // true si on peut utiliser IPv4 ET IPv6
	UseIPv6      bool // true si connecté via IPv6
	mu           sync.RWMutex
	connected    bool
	lastResponse time.Time
}

var globalNetConfig = &NetworkConfig{}

// GetNetworkConfig retourne la configuration réseau globale
func GetNetworkConfig() *NetworkConfig {
	return globalNetConfig
}

// SetConnected marque la connexion comme établie
func (nc *NetworkConfig) SetConnected() {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.connected = true
	nc.lastResponse = time.Now()
}

// IsConnected retourne si on est connecté
func (nc *NetworkConfig) IsConnected() bool {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.connected
}

// networkConfig représente une configuration réseau à essayer
type networkConfig struct {
	name      string
	network   string // "udp", "udp4", "udp6"
	listen    string
	server    string
	dualStack bool
	isIPv6    bool
}

// buildNetworkConfigs construit la liste des configurations selon l'OS
// Windows nécessite un traitement spécial car IPV6_V6ONLY=true par défaut
func buildNetworkConfigs() []networkConfig {
	configs := []networkConfig{}

	switch runtime.GOOS {
	case "windows":
		// Windows: On essaie d'abord dual-stack via "udp" (Go gère IPV6_V6ONLY)
		// Mais on ajoute aussi IPv4-only et IPv6-only séparément comme fallback
		configs = append(configs,
			// Essayer dual-stack (Go désactive automatiquement IPV6_V6ONLY sur Windows)
			networkConfig{"Dual-Stack (via IPv6)", "udp", "[::]:8080", protocol.ServerUDPv6, true, true},
			networkConfig{"Dual-Stack (via IPv4)", "udp", "[::]:8080", protocol.ServerUDPv4, true, false},
			// Fallback: IPv4 uniquement
			networkConfig{"IPv4 uniquement", "udp4", "0.0.0.0:8080", protocol.ServerUDPv4, false, false},
			// Fallback: IPv6 uniquement (si dual-stack échoue mais IPv6 disponible)
			networkConfig{"IPv6 uniquement", "udp6", "[::]:8080", protocol.ServerUDPv6, false, true},
		)
	default:
		// Linux/macOS/WSL: [::]:8080 capture IPv4+IPv6 par défaut
		configs = append(configs,
			// Dual-stack : socket IPv6 qui peut aussi recevoir IPv4
			networkConfig{"Dual-Stack (via IPv6)", "udp", "[::]:8080", protocol.ServerUDPv6, true, true},
			networkConfig{"Dual-Stack (via IPv4)", "udp", "[::]:8080", protocol.ServerUDPv4, true, false},
			// Fallback IPv4 uniquement
			networkConfig{"IPv4 uniquement", "udp4", "0.0.0.0:8080", protocol.ServerUDPv4, false, false},
		)
	}
	return configs
}

// TryConnectWithFallback essaie de se connecter avec dual-stack d'abord, puis IPv4
//
// DUAL-STACK expliqué:
// - Linux: Un socket [::]:port capture IPv4 ET IPv6 (IPv4-mapped addresses: ::ffff:x.x.x.x)
// - Windows: Par défaut, [::]:port capture SEULEMENT IPv6 (IPV6_V6ONLY=true par défaut)
// - Go gère automatiquement cette différence sur Windows quand on utilise "udp" (pas "udp6")
//
// Stratégies essayées dans l'ordre:
// 1. Dual-stack IPv6-first: socket [::]:8080 + serveur IPv6
// 2. Dual-stack IPv4-first: socket [::]:8080 + serveur IPv4
// 3. IPv4 uniquement: socket 0.0.0.0:8080 + serveur IPv4
func TryConnectWithFallback(myName string, privKey *ecdsa.PrivateKey) (*net.UDPConn, *net.UDPAddr, error) {
	fmt.Printf("🖥️  OS détecté: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	configs := buildNetworkConfigs()

	for _, cfg := range configs {
		fmt.Printf("🔄 Tentative: %s...\n", cfg.name)

		// Ouvrir le socket UDP
		localAddr, err := net.ResolveUDPAddr(cfg.network, cfg.listen)
		if err != nil {
			fmt.Printf("   ❌ Impossible de résoudre l'adresse locale: %v\n", err)
			continue
		}

		conn, err := net.ListenUDP(cfg.network, localAddr)
		if err != nil {
			fmt.Printf("   ❌ Impossible d'ouvrir le port: %v\n", err)
			continue
		}

		// Résoudre l'adresse du serveur
		serverAddr, err := net.ResolveUDPAddr("udp", cfg.server)
		if err != nil {
			fmt.Printf("   ❌ Impossible de résoudre le serveur: %v\n", err)
			conn.Close()
			continue
		}

		// Tester la connexion avec un Hello + attente de réponse
		fmt.Printf("   📤 Envoi Hello au serveur %s...\n", cfg.server)

		// Envoyer Hello
		_, err = SendHello(conn, serverAddr, myName, privKey)
		if err != nil {
			fmt.Printf("   ❌ Erreur envoi Hello: %v\n", err)
			conn.Close()
			continue
		}

		// Attendre une réponse avec timeout
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(buffer)
		conn.SetReadDeadline(time.Time{}) // Réinitialiser le deadline

		if err != nil {
			fmt.Printf("   ❌ Pas de réponse du serveur (timeout): %v\n", err)
			conn.Close()
			continue
		}

		// Vérifier que c'est bien un HelloReply (type 130)
		if n >= 7 && buffer[4] == protocol.HelloReply {
			fmt.Printf("   ✅ Connexion %s établie! (HelloReply reçu)\n", cfg.name)

			// Sauvegarder la config
			globalNetConfig.mu.Lock()
			globalNetConfig.ServerAddr = serverAddr
			globalNetConfig.DualStack = cfg.dualStack
			globalNetConfig.UseIPv6 = cfg.isIPv6
			globalNetConfig.connected = true
			globalNetConfig.lastResponse = time.Now()
			globalNetConfig.mu.Unlock()

			// IMPORTANT: Envoyer aussi un Hello sur l'autre protocole pour publier les deux adresses
			// Cela permet aux peers IPv4-only et IPv6-only de nous contacter
			if cfg.dualStack {
				// On est en dual-stack, envoyer Hello sur l'autre adresse du serveur
				var otherServer string
				if cfg.isIPv6 {
					otherServer = protocol.ServerUDPv4
				} else {
					otherServer = protocol.ServerUDPv6
				}
				otherAddr, err := net.ResolveUDPAddr("udp", otherServer)
				if err == nil {
					fmt.Printf("   📤 Envoi Hello supplémentaire à %s pour publier les deux adresses...\n", otherServer)
					SendHello(conn, otherAddr, myName, privKey)
					// Attendre brièvement la réponse (pas bloquant si pas de réponse)
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					conn.ReadFromUDP(buffer)
					conn.SetReadDeadline(time.Time{})
				}
			}

			return conn, serverAddr, nil
		}

		fmt.Printf("   ⚠️ Réponse inattendue (type=%d)\n", buffer[4])
		conn.Close()
	}

	return nil, nil, fmt.Errorf("impossible de se connecter au serveur (toutes les méthodes ont échoué)")
}

// ResolveAddrWithFallback résout une adresse en essayant IPv6 puis IPv4
func ResolveAddrWithFallback(addrStr string) (*net.UDPAddr, error) {
	// Essayer de résoudre directement
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err == nil {
		return addr, nil
	}

	// Si l'adresse contient un hostname, essayer de le résoudre
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, fmt.Errorf("adresse invalide: %s", addrStr)
	}

	// Résoudre le hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("impossible de résoudre %s: %v", host, err)
	}

	// Selon notre configuration réseau, préférer IPv4 ou IPv6
	globalNetConfig.mu.RLock()
	preferIPv4 := !globalNetConfig.UseIPv6
	globalNetConfig.mu.RUnlock()

	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = ip
		} else {
			ipv6 = ip
		}
	}

	var selectedIP net.IP
	if preferIPv4 && ipv4 != nil {
		selectedIP = ipv4
	} else if ipv6 != nil {
		selectedIP = ipv6
	} else if ipv4 != nil {
		selectedIP = ipv4
	} else {
		return nil, fmt.Errorf("aucune adresse IP trouvée pour %s", host)
	}

	// Construire l'adresse finale
	var finalAddr string
	if selectedIP.To4() != nil {
		finalAddr = fmt.Sprintf("%s:%s", selectedIP.String(), port)
	} else {
		finalAddr = fmt.Sprintf("[%s]:%s", selectedIP.String(), port)
	}

	return net.ResolveUDPAddr("udp", finalAddr)
}

// SelectBestAddress sélectionne la meilleure adresse parmi plusieurs (IPv4 ou IPv6 selon config)
// En mode Dual-Stack: on peut utiliser IPv4 ET IPv6
// En mode IPv4 uniquement: on ne peut utiliser QUE des adresses IPv4
func SelectBestAddress(addresses []string) string {
	if len(addresses) == 0 {
		return ""
	}

	globalNetConfig.mu.RLock()
	dualStack := globalNetConfig.DualStack
	useIPv6 := globalNetConfig.UseIPv6
	globalNetConfig.mu.RUnlock()

	var ipv4Addr, ipv6Addr string

	for _, addr := range addresses {
		addr = trimAddress(addr)
		if addr == "" {
			continue
		}

		// Détecter si c'est IPv6 (contient '[' ou plus de ':')
		isIPv6 := IsIPv6Address(addr)

		if isIPv6 {
			if ipv6Addr == "" {
				ipv6Addr = addr
			}
		} else {
			if ipv4Addr == "" {
				ipv4Addr = addr
			}
		}
	}

	// En mode Dual-Stack: on peut utiliser les deux
	if dualStack {
		// Préférer IPv6 si on est connecté via IPv6, sinon IPv4
		if useIPv6 && ipv6Addr != "" {
			return ipv6Addr
		}
		if ipv4Addr != "" {
			return ipv4Addr
		}
		return ipv6Addr // Fallback sur IPv6 si pas d'IPv4
	}

	// En mode IPv4 uniquement: on ne peut utiliser QUE des adresses IPv4
	if ipv4Addr != "" {
		return ipv4Addr
	}

	// Pas d'adresse IPv4 disponible et on n'est pas en dual-stack -> impossible
	return ""
}

// IsIPv6Address détecte si une adresse est IPv6
func IsIPv6Address(addr string) bool {
	if len(addr) == 0 {
		return false
	}
	// IPv6 avec crochets: [::1]:8080
	if addr[0] == '[' {
		return true
	}
	// IPv6 sans crochets: plus d'un ':' (IPv4 n'a qu'un seul ':' pour le port)
	return countColons(addr) > 1
}

// CanCommunicateWith vérifie si on peut communiquer avec une adresse donnée
func CanCommunicateWith(addr string) bool {
	if addr == "" {
		return false
	}

	globalNetConfig.mu.RLock()
	dualStack := globalNetConfig.DualStack
	globalNetConfig.mu.RUnlock()

	// En mode Dual-Stack: on peut communiquer avec tout
	if dualStack {
		return true
	}

	// En mode IPv4 uniquement: on ne peut communiquer qu'avec des IPv4
	isTargetIPv6 := IsIPv6Address(addr)
	return !isTargetIPv6
}

// GetNetworkMode retourne une description du mode réseau actuel
func GetNetworkMode() string {
	globalNetConfig.mu.RLock()
	defer globalNetConfig.mu.RUnlock()
	if globalNetConfig.DualStack {
		return "Dual-Stack (IPv4+IPv6)"
	}
	return "IPv4 uniquement"
}

func trimAddress(addr string) string {
	// Supprimer les espaces et retours à la ligne
	result := ""
	for _, c := range addr {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			result += string(c)
		}
	}
	return result
}

func countColons(s string) int {
	count := 0
	for _, c := range s {
		if c == ':' {
			count++
		}
	}
	return count
}
