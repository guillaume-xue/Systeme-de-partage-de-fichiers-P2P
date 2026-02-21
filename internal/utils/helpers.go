package utils

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// FormatBytesInt64 formate une taille en bytes de façon lisible
func FormatBytesInt64(byteCount int64) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

// parseHash convertit une chaîne hexadécimale en hash [32]byte
// Accepte les formats: "abc123...", "0xabc123...", avec ou sans espaces
func ParseHash(s string) ([32]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) > 64 {
		s = s[:64]
	}
	hash, err := hex.DecodeString(s)
	if err != nil || len(hash) != 32 {
		return [32]byte{}, fmt.Errorf("❌ Hash invalide")
	}
	var h [32]byte
	copy(h[:], hash)
	return h, nil
}

func CleanName(pName string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, pName)
}

// DetectLocalIPProtocol détecte si on supporte IPv4 et/ou IPv6
// en vérifiant les interfaces réseau locales
func DetectLocalIPProtocol() (hasIPv4, hasIPv6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	return
}

// IsIPv4 vérifie si une adresse UDP est IPv4
func IsIPv4(addr *net.UDPAddr) bool {
	return addr.IP.To4() != nil
}

func SeparateAddressesByProtocol(filteredTargets []*net.UDPAddr) ([]*net.UDPAddr, []*net.UDPAddr) {
	var targetIPv4, targetIPv6 []*net.UDPAddr
	for _, addr := range filteredTargets {
		if IsIPv4(addr) {
			targetIPv4 = append(targetIPv4, addr)
		} else {
			targetIPv6 = append(targetIPv6, addr)
		}
	}

	return targetIPv4, targetIPv6
}

func AddrParserSolver(rawAddr string) (targets []*net.UDPAddr) {
	lines := strings.SplitSeq(rawAddr, "\n")
	for addrLine := range lines {
		addrLine = strings.TrimSpace(addrLine)
		if addrLine == "" {
			continue
		}
		if resolvedAddr, err := net.ResolveUDPAddr("udp", addrLine); err == nil {
			targets = append(targets, resolvedAddr)
			ipVersion := "IPv4"
			if !IsIPv4(resolvedAddr) {
				ipVersion = "IPv6"
			}
			fmt.Printf("-> Trouvé: %s [%s]\n", addrLine, ipVersion)
		}
	}
	return targets
}

func CalExpo2Time(count int) time.Duration {
	totalTimeout := time.Duration(0)
	for i := 1; i < count; i++ {
		totalTimeout += time.Duration(1<<uint(i-1)) * time.Second
	}
	return totalTimeout
}
