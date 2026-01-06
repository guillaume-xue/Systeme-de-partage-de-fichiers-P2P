package utils

import (
	"encoding/hex"
	"fmt"
	"main/internal/protocol"
	"net"
	"strings"
)

// Formate une taille en bytes de façon lisible (int64 au cas où si très gros fichiers)
func FormatBytesInt64(byteCount int64) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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

// detectLocalIPProtocol détecte si on supporte IPv4 et/ou IPv6
func DetectLocalIPProtocol() (hasIPv4 bool, hasIPv6 bool) {
	// Tester IPv4
	if _, err := net.ResolveUDPAddr("udp4", protocol.GetServerUDPv4()); err == nil {
		hasIPv4 = true
	}

	// Tester IPv6
	if _, err := net.ResolveUDPAddr("udp6", protocol.GetServerUDPv6()); err == nil {
		hasIPv6 = true
	}

	return hasIPv4, hasIPv6
}


func FiltrerAddressesByProtocol(filteredTargets, filteredRelayAddrs []*net.UDPAddr) (bool, []*net.UDPAddr, []*net.UDPAddr, []*net.UDPAddr, []*net.UDPAddr) {

	// Séparer les adresses par protocole
	var targetIPv4, targetIPv6 []*net.UDPAddr
	for _, addr := range filteredTargets {
		if addr.IP.To4() != nil {
			targetIPv4 = append(targetIPv4, addr)
		} else {
			targetIPv6 = append(targetIPv6, addr)
		}
	}

	var relayIPv4, relayIPv6 []*net.UDPAddr
	for _, addr := range filteredRelayAddrs {
		if addr.IP.To4() != nil {
			relayIPv4 = append(relayIPv4, addr)
		} else {
			relayIPv6 = append(relayIPv6, addr)
		}
	}

	// Vérifier qu'il y a au moins un protocole compatible
	hasCompatibleProtocol := (len(targetIPv4) > 0 && len(relayIPv4) > 0) ||
		(len(targetIPv6) > 0 && len(relayIPv6) > 0)

	if !hasCompatibleProtocol {
		return false, nil, nil, nil, nil
	}

	return true, targetIPv4, targetIPv6, relayIPv4, relayIPv6
}
