package merkle

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	TypeChunk        = 0 // data pure
	TypeDirectory    = 1 // Répertoire
	TypeBig          = 2 // Fichier fragmenté
	TypeBigDirectory = 3 // Répertoire fragmenté

	MaxChunkSize   = 1024
	MaxDirEntries  = 16
	MaxBigChildren = 32
	FileNameSize   = 32
	HashSize       = 32
	DirEntrySize   = FileNameSize + HashSize // Taille d'une entrée de répertoire (32 nom + 32 hash)
)

// DirEntry: une ligne dans un répertoire
type DirEntry struct {
	Name [32]byte
	Hash [32]byte
}

// Store : stockage thread-safe des datums
type Store struct {
	data map[[32]byte][]byte
	mu   sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		data: make(map[[32]byte][]byte),
	}
}

func (s *Store) Add(datum []byte) [32]byte {
	hash := sha256.Sum256(datum)
	s.Set(hash, datum)
	return hash
}

func (s *Store) Set(hash [32]byte, datum []byte) {
	s.mu.Lock()
	s.data[hash] = datum
	s.mu.Unlock()
}

func (s *Store) Get(hash [32]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.data[hash]
	return data, ok
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// CreateChunk : [Type 0] [Data...]
func CreateChunk(data []byte) ([]byte, [32]byte) {
	if len(data) > MaxChunkSize {
		panic(fmt.Sprintf("❌ La taille du chunk dépasse %d octets", MaxChunkSize))
	}
	datum := make([]byte, 1+len(data))
	datum[0] = TypeChunk
	copy(datum[1:], data)
	return datum, sha256.Sum256(datum)
}

// CreateDirectoryNode : [Type 1] [Entry1] [Entry2] ...
func CreateDirectoryNode(entries []DirEntry) ([]byte, [32]byte) {
	if len(entries) > MaxDirEntries {
		panic(fmt.Sprintf("❌ Directory ne peut pas avoir plus de %d entrées, a %d", MaxDirEntries, len(entries)))
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
	if len(hashes) > MaxBigChildren {
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
	buffer := make([]byte, MaxChunkSize)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			datum, _ := CreateChunk(buffer[:n])
			hash := store.Add(datum)
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
		datum, _ := CreateChunk([]byte{})
		hash := store.Add(datum)
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

	// 	Découpage en blocs de MaxDirEntries
	var childHashes [][32]byte
	for i := 0; i < len(dirEntries); i += MaxDirEntries {
		end := min(i+MaxDirEntries, len(dirEntries))
		datum, _ := CreateDirectoryNode(dirEntries[i:end])
		hash := store.Add(datum)
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

	for i := 0; i < len(hashes); i += MaxBigChildren {
		end := min(i+MaxBigChildren, len(hashes))

		group := hashes[i:end]
		if len(group) == 1 && len(hashes) == 1 {
			return group[0]
		}

		datum, _ := CreateBigNode(nodeType, group)
		hash := store.Add(datum)
		parentHashes = append(parentHashes, hash)
	}

	return buildRecursive(store, parentHashes, nodeType)
}

func ParseDatum(datum []byte) (uint8, []byte) {
	if len(datum) == 0 {
		return 0, nil
	}
	return datum[0], datum[1:]
}

func ParseDirectoryEntries(data []byte) []DirEntry {
	count := len(data) / DirEntrySize
	entries := make([]DirEntry, count)
	for i := range count {
		start := i * DirEntrySize
		copy(entries[i].Name[:], data[start:start+FileNameSize])
		copy(entries[i].Hash[:], data[start+FileNameSize:start+DirEntrySize])
	}
	return entries
}

func ParseBigHashes(data []byte) [][32]byte {
	count := len(data) / HashSize
	hashes := make([][32]byte, count)
	for i := range count {
		copy(hashes[i][:], data[i*HashSize:(i+1)*HashSize])
	}
	return hashes
}

// Helper retourne le nom d'une entrée (sans les octets nuls)
func GetEntryName(e DirEntry) string {
	for i, b := range e.Name[:] {
		if b == 0 {
			return string(e.Name[:i])
		}
	}
	return string(e.Name[:])
}
