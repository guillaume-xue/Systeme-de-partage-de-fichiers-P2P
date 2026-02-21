package merkle

import (
	"crypto/sha256"
	"fmt"
	"io"
	"main/internal/config"
	"os"
	"path/filepath"
)

const (
	TypeChunk        = 0 // data pure
	TypeDirectory    = 1 // Répertoire
	TypeBig          = 2 // Fichier fragmenté
	TypeBigDirectory = 3 // Répertoire fragmenté

	FileNameSize = 32
	HashSize     = 32
	DirEntrySize = FileNameSize + HashSize // Taille d'une entrée de répertoire (32 nom + 32 hash)
)

// Valeurs paramétrables depuis la config (remplace les anciennes constantes)
func GetMaxChunkSize() int {
	return config.GlobalConfig.Merkle.MaxChunkSize
}

func GetMaxDirEntries() int {
	return config.GlobalConfig.Merkle.MaxDirEntries
}

func GetMaxBigChildren() int {
	return config.GlobalConfig.Merkle.MaxBigChildren
}

// DirEntry: une ligne dans un répertoire
type DirEntry struct {
	Name [32]byte
	Hash [32]byte
}

// Store : stockage thread-safe des datums

// CreateChunk : [Type 0] [Data...]
func CreateChunk(data []byte) ([]byte, [32]byte) {
	if len(data) > GetMaxChunkSize() {
		panic(fmt.Sprintf("❌ La taille du chunk dépasse %d octets", GetMaxChunkSize()))
	}
	datum := make([]byte, 1+len(data))
	datum[0] = TypeChunk
	copy(datum[1:], data)
	return datum, sha256.Sum256(datum)
}

// CreateDirectoryNode : [Type 1] [Entry1] [Entry2] ...
func CreateDirectoryNode(entries []DirEntry) ([]byte, [32]byte) {
	if len(entries) > GetMaxDirEntries() {
		panic(fmt.Sprintf("❌ Directory ne peut pas avoir plus de %d entrées, a %d", GetMaxDirEntries(), len(entries)))
	}
	datum := make([]byte, 1+len(entries)*DirEntrySize)
	datum[0] = TypeDirectory
	for i, e := range entries {
		offset := 1 + i*DirEntrySize
		copy(datum[offset:], e.Name[:])
		copy(datum[offset+FileNameSize:], e.Hash[:])
	}
	return datum, sha256.Sum256(datum)
}

// CreateBigNode (pour Type 2 et 3) : [Type X] [Hash1] [Hash2] ...
func CreateBigNode(nodeType uint8, hashes [][32]byte) ([]byte, [32]byte) {
	if len(hashes) > GetMaxBigChildren() {
		panic(fmt.Sprintf("❌ Trop d'enfant pour un noeud,  %d", len(hashes)))
	}
	datum := make([]byte, 1+len(hashes)*HashSize)
	datum[0] = nodeType
	for i, hash := range hashes {
		copy(datum[1+i*HashSize:], hash[:])
	}
	return datum, sha256.Sum256(datum)
}

func FileToMerkle(store *Store, filePath string) ([32]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()

	var chunkHashes [][32]byte
	buffer := make([]byte, GetMaxChunkSize())

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			datum, hash := CreateChunk(buffer[:n])
			store.Set(hash, datum)
			chunkHashes = append(chunkHashes, hash)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return [32]byte{}, err
		}
	}

	// Cas vide
	if len(chunkHashes) == 0 {
		datum, hash := CreateChunk([]byte{})
		store.Set(hash, datum)
		return hash, nil
	}
	return buildRecursive(store, chunkHashes, TypeBig), nil
}

func DirToMerkle(store *Store, dirPath string) ([32]byte, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return [32]byte{}, err
	}

	var dirEntries []DirEntry

	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		} // Ignore les fichiers illisibles
		name := e.Name()
		if len(name) > FileNameSize {
			name = name[:FileNameSize] // Tronquer si trop long
		}

		fullPath := filepath.Join(dirPath, e.Name())
		var hash [32]byte
		if info.IsDir() {
			hash, err = DirToMerkle(store, fullPath)
		} else {
			hash, err = FileToMerkle(store, fullPath)
		}
		if err == nil {
			res := DirEntry{Hash: hash}
			copy(res.Name[:], []byte(name))
			dirEntries = append(dirEntries, res)
		}
	}

	// 	Découpage en blocs de GetMaxDirEntries()
	var childHashes [][32]byte
	for i := 0; i < len(dirEntries); i += GetMaxDirEntries() {
		end := min(i+GetMaxDirEntries(), len(dirEntries))
		datum, hash := CreateDirectoryNode(dirEntries[i:end])
		store.Set(hash, datum)
		childHashes = append(childHashes, hash)
	}
	return buildRecursive(store, childHashes, TypeBigDirectory), nil
}

// Construction récursive de l'arbre vers le haut
func buildRecursive(store *Store, hashes [][32]byte, nodeType uint8) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	var parentHashes [][32]byte

	for i := 0; i < len(hashes); i += GetMaxBigChildren() {
		end := min(i+GetMaxBigChildren(), len(hashes))

		group := hashes[i:end]
		if len(group) == 1 && len(hashes) == 1 {
			return group[0]
		}

		datum, hash := CreateBigNode(nodeType, group)
		store.Set(hash, datum)
		parentHashes = append(parentHashes, hash)
	}

	return buildRecursive(store, parentHashes, nodeType)
}
