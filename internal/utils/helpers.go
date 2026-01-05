package utils

import (
	"encoding/hex"
	"fmt"
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
