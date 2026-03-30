package merkle

import (
	"fmt"
	"strings"
)

// DatumFetcher est une fonction qui récupère un datum par son hash.
// Utilisé pour la résolution lazy de chemins dans l'arbre Merkle.
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

		nodeType, nodeData := ParseDatum(datum)

		switch nodeType {
		case TypeDirectory:
			entries := ParseDirectoryEntries(nodeData)
			childHash, err := findEntryByName(entries, part)
			if err != nil {
				return [32]byte{}, fmt.Errorf("entrée '%s' introuvable dans le répertoire %x", part, currentHash)
			}
			currentHash = childHash

		case TypeBigDirectory:
			// BigDirectory pointe vers des sous-nœuds Directory, on les parcourt un par un
			subHashes := ParseBigHashes(nodeData)
			found := false
			for _, subHash := range subHashes {
				subDatum, err := fetcher(subHash)
				if err != nil {
					continue // Sous-nœud inaccessible, on essaie le suivant
				}
				subType, subData := ParseDatum(subDatum)
				if subType == TypeDirectory {
					entries := ParseDirectoryEntries(subData)
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
func findEntryByName(entries []DirEntry, name string) ([32]byte, error) {
	for _, e := range entries {
		if GetEntryName(e) == name {
			return e.Hash, nil
		}
	}
	return [32]byte{}, fmt.Errorf("not found")
}
