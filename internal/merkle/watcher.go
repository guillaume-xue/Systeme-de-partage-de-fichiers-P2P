package merkle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// computeDirFingerprint calcule une empreinte rapide du dossier
// basée sur les noms, tailles et dates de modification des fichiers.
// Cela permet de détecter les changements sans reconstruire tout le Merkle tree.
func computeDirFingerprint(dirPath string) (string, error) {
	var fingerprint string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Ignorer les fichiers inaccessibles
		}
		rel, _ := filepath.Rel(dirPath, path)
		fingerprint += fmt.Sprintf("%s|%d|%d;", rel, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	return fingerprint, err
}

// OnRootChanged est le type de callback appelé quand le root hash change
type OnRootChanged func(store *Store, newRoot [32]byte)

// WatchSharedDir surveille le dossier partagé à intervalle régulier.
// Si des modifications sont détectées, le Merkle tree est reconstruit
// et le callback est appelé avec le nouveau store et root hash.
func WatchSharedDir(ctx context.Context, sharedDir string, interval time.Duration, onChange OnRootChanged) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Calculer l'empreinte initiale
	lastFingerprint, _ := computeDirFingerprint(sharedDir)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentFingerprint, err := computeDirFingerprint(sharedDir)
			if err != nil {
				continue
			}

			// Pas de changement détecté
			if currentFingerprint == lastFingerprint {
				continue
			}
			lastFingerprint = currentFingerprint

			// Reconstruire le Merkle tree
			newStore := NewStore()
			newRoot, err := DirToMerkle(newStore, sharedDir)
			if err != nil {
				fmt.Printf("⚠️  Erreur lors de la reconstruction du Merkle tree: %v\n", err)
				continue
			}

			fmt.Printf("🔄 Changement détecté dans le dossier partagé, mise à jour du Merkle tree (root: %x...)\n", newRoot[:8])
			onChange(newStore, newRoot)
		}
	}
}
