// Package utils contient les fonctions utilitaires partagées dans tout le projet
package utils

import (
	"fmt"
)

// ===========================================================================
// Formatage des tailles
// ===========================================================================

// FormatBytes formate une taille en bytes de façon lisible (int)
func FormatBytes(byteCount int) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

// FormatBytesInt64 formate une taille en bytes de façon lisible (int64)
func FormatBytesInt64(byteCount int64) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

// ===========================================================================
// Fonctions mathématiques
// ===========================================================================

// MinInt retourne le minimum de deux entiers
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt retourne le maximum de deux entiers
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ===========================================================================
// Fonctions de texte
// ===========================================================================

// IsTextData vérifie si les données sont du texte ASCII affichable
func IsTextData(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
		if b > 126 {
			return false
		}
	}
	return true
}
