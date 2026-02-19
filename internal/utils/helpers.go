package utils

import (
	"encoding/hex"
	"fmt"
	"main/internal/merkle"
	"main/internal/protocol"
	"net"
	"strings"
	"time"
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
	if _, err := net.ResolveUDPAddr("udp4", protocol.GetServerUDPv4()); err == nil {
		hasIPv4 = true
	}
	if _, err := net.ResolveUDPAddr("udp6", protocol.GetServerUDPv6()); err == nil {
		hasIPv6 = true
	}
	return hasIPv4, hasIPv6
}

func SeperateAddressesByProtocol(filteredTargets []*net.UDPAddr) ([]*net.UDPAddr, []*net.UDPAddr) {
	// Séparer les adresses par protocole
	var targetIPv4, targetIPv6 []*net.UDPAddr
	for _, addr := range filteredTargets {
		if addr.IP.To4() != nil {
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
			if resolvedAddr.IP.To4() == nil {
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

// Une interface pour gérer d'où viennent les données (DL arbo ou DL disque)
type DatumProvider interface {
	Get(hash [32]byte) ([]byte, bool)
}

// DatumFetcher est une fonction qui récupère un datum par son hash.
type DatumFetcher func(hash [32]byte) ([]byte, error)

// ResolvePathLazy résout un chemin dans le Merkle tree en mode lazy :
// ne télécharge que les datums nécessaires pour suivre le chemin, un par un.
// fetcher est appelé pour chaque nœud à visiter (fait la requête réseau si absent du cache).
func ResolvePathLazy(fetcher DatumFetcher, rootHash [32]byte, path string) ([32]byte, error) {
	// Nettoyer le chemin
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	if path == "" || path == "." {
		return rootHash, nil
	}

	parts := strings.Split(path, "/")
	currentHash := rootHash

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}

		datum, err := fetcher(currentHash)
		if err != nil {
			return [32]byte{}, fmt.Errorf("impossible de récupérer le datum %x : %v", currentHash, err)
		}

		nodeType, nodeData := merkle.ParseDatum(datum)

		switch nodeType {
		case merkle.TypeDirectory:
			entries := merkle.ParseDirectoryEntries(nodeData)
			childHash, err := findEntryByName(entries, part)
			if err != nil {
				return [32]byte{}, fmt.Errorf("entrée '%s' introuvable dans le répertoire %x", part, currentHash)
			}
			currentHash = childHash

		case merkle.TypeBigDirectory:
			// BigDirectory pointe vers des sous-nœuds Directory, on les parcourt un par un
			subHashes := merkle.ParseBigHashes(nodeData)
			found := false
			for _, subHash := range subHashes {
				subDatum, err := fetcher(subHash)
				if err != nil {
					continue // Sous-nœud inaccessible, on essaie le suivant
				}
				subType, subData := merkle.ParseDatum(subDatum)
				if subType == merkle.TypeDirectory {
					entries := merkle.ParseDirectoryEntries(subData)
					childHash, err := findEntryByName(entries, part)
					if err == nil {
						currentHash = childHash
						found = true
						break
					}
				}
			}
			if !found {
				return [32]byte{}, fmt.Errorf("entrée '%s' introuvable dans le big-répertoire %x", part, currentHash)
			}

		default:
			return [32]byte{}, fmt.Errorf("le chemin traverse un nœud non-répertoire (type %d) à %x", nodeType, currentHash)
		}
	}

	return currentHash, nil
}

// findEntryByName cherche une entrée par nom dans une liste de DirEntry
func findEntryByName(entries []merkle.DirEntry, name string) ([32]byte, error) {
	for _, e := range entries {
		if merkle.GetEntryName(e) == name {
			return e.Hash, nil
		}
	}
	return [32]byte{}, fmt.Errorf("not found")
}

func PrintTree(provider DatumProvider, hash [32]byte, prefix, fileName string, isLast bool) {
	datum, found := provider.Get(hash)

	marker := "├── "
	if isLast {
		marker = "└── "
	}

	if !found {
		fmt.Printf("%s%s [???] nom: %s (manquant) %x\n", prefix, marker, fileName, hash)
		return
	}
	nodeType, nodeData := merkle.ParseDatum(datum)

	newPrefix := prefix + "│   "
	if isLast {
		newPrefix = prefix + "    "
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(nodeData)
		fmt.Printf("%s%s%s 📁 [DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			PrintTree(provider, e.Hash, newPrefix, merkle.GetEntryName(e), i == len(entries)-1)
		}
	case merkle.TypeBigDirectory:
		entries := merkle.ParseBigHashes(nodeData)
		fmt.Printf("%s%s%s 📁 [BIG-DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			PrintTree(provider, e, newPrefix, "", i == len(entries)-1)
		}
	case merkle.TypeChunk:
		fmt.Printf("%s%s%s 📄 [FILE] (%s) %x\n", prefix, marker, fileName, FormatBytesInt64(int64(len(nodeData))), hash)

	case merkle.TypeBig:
		fmt.Printf("%s%s%s 📄 [BIG-FILE] (%s) %x\n", prefix, marker, fileName, FormatBytesInt64(int64(len(nodeData))), hash)
	}
}
