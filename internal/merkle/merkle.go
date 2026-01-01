package merkle

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Types de nœuds Merkle selon le protocole
const (
	TypeChunk        = 0 // Données brutes (≤ 1024 octets)
	TypeDirectory    = 1 // Répertoire (≤ 16 entrées)
	TypeBig          = 2 // Gros fichier (2-32 enfants)
	TypeBigDirectory = 3 // Gros répertoire (2-32 enfants)

	MaxChunkSize   = 1024 // Taille max d'un chunk
	MaxDirEntries  = 16   // Nombre max d'entrées dans un Directory
	MaxBigChildren = 32   // Nombre max d'enfants dans un Big/BigDirectory
	DirEntrySize   = 64   // Taille d'une entrée de répertoire (32 nom + 32 hash)
	HashSize       = 32   // Taille d'un hash SHA-256
	FileNameSize   = 32   // Taille max du nom de fichier
)

// Node représente un noeud dans l'arbre de Merkle
type Node struct {
	Type     uint8    // Type du noeud (Chunk, Directory, Big, BigDirectory)
	Data     []byte   // Données du noeud (contenu sérialisé)
	Hash     [32]byte // Hash SHA-256 du noeud
	Children []Node   // Enfants (pour Big et BigDirectory)
}

// DirEntry représente une entrée de répertoire
type DirEntry struct {
	Name [32]byte // Nom du fichier (padded avec des 0)
	Hash [32]byte // Hash du contenu
}

// Store stocke tous les datums par leur hash (thread-safe)
type Store struct {
	Data map[[32]byte][]byte // Hash -> Datum (type + data)
	mu   sync.RWMutex
}

// HashData calcule le hash SHA-256 des données
func HashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// NewStore crée un nouveau store vide
func NewStore() *Store {
	return &Store{
		Data: make(map[[32]byte][]byte),
	}
}

// Add ajoute un datum au store et retourne son hash
func (s *Store) Add(datum []byte) [32]byte {
	hash := HashData(datum)
	s.Set(hash, datum)
	return hash
}

// Set ajoute un datum avec un hash connu
func (s *Store) Set(hash [32]byte, datum []byte) {
	s.mu.Lock()
	s.Data[hash] = datum
	s.mu.Unlock()
}

// Get récupère un datum par son hash
func (s *Store) Get(hash [32]byte) ([]byte, bool) {
	s.mu.RLock()
	data, ok := s.Data[hash]
	s.mu.RUnlock()
	return data, ok
}

// Len retourne le nombre de datums
func (s *Store) Len() int {
	s.mu.RLock()
	n := len(s.Data)
	s.mu.RUnlock()
	return n
}

// Clear vide le store
func (s *Store) Clear() {
	s.mu.Lock()
	s.Data = make(map[[32]byte][]byte)
	s.mu.Unlock()
}

// Delete supprime un datum
func (s *Store) Delete(hash [32]byte) {
	s.mu.Lock()
	delete(s.Data, hash)
	s.mu.Unlock()
}

// Itération sur tous les datums (thread-safe)
func (s *Store) Range(fn func(hash [32]byte, datum []byte) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for hash, datum := range s.Data {
		if !fn(hash, datum) {
			break
		}
	}
}

// CreateChunk crée un noeud Chunk à partir de données (≤ 1024 octets)
func CreateChunk(data []byte) ([]byte, [32]byte) {
	if len(data) > MaxChunkSize {
		panic(fmt.Sprintf("❌ La taille du chunk dépasse %d octets", MaxChunkSize))
	}
	// Format: [Type (1 byte)] [Data]
	datum := make([]byte, 1+len(data))
	datum[0] = TypeChunk
	copy(datum[1:], data)

	hash := HashData(datum)
	return datum, hash
}

// CreateBigNode crée un noeud Big à partir d'une liste de hashes enfants
func CreateBigNode(childHashes [][32]byte) ([]byte, [32]byte) {
	if len(childHashes) < 2 || len(childHashes) > MaxBigChildren {
		panic(fmt.Sprintf("❌ Big doit avoir 2-32 enfants, a %d", len(childHashes)))
	}
	// Format: [Type (1 byte)] [Hash1 (32 bytes)] [Hash2 (32 bytes)] ...
	datum := make([]byte, 1+len(childHashes)*HashSize)
	datum[0] = TypeBig
	for i, h := range childHashes {
		copy(datum[1+i*HashSize:], h[:])
	}

	hash := HashData(datum)
	return datum, hash
}

// CreateDirectoryNode crée un noeud Directory à partir d'entrées
func CreateDirectoryNode(entries []DirEntry) ([]byte, [32]byte) {
	if len(entries) > MaxDirEntries {
		panic(fmt.Sprintf("❌ Directory ne peut pas avoir plus de %d entrées, a %d", MaxDirEntries, len(entries)))
	}
	// Format: [Type (1 byte)] [Entry1 (64 bytes)] [Entry2 (64 bytes)] ...
	datum := make([]byte, 1+len(entries)*DirEntrySize)
	datum[0] = TypeDirectory
	for i, e := range entries {
		offset := 1 + i*DirEntrySize
		copy(datum[offset:offset+FileNameSize], e.Name[:])
		copy(datum[offset+FileNameSize:offset+DirEntrySize], e.Hash[:])
	}

	hash := HashData(datum)
	return datum, hash
}

// CreateBigDirectoryNode crée un noeud BigDirectory à partir de hashes enfants
func CreateBigDirectoryNode(childHashes [][32]byte) ([]byte, [32]byte) {
	if len(childHashes) < 2 || len(childHashes) > MaxBigChildren {
		panic(fmt.Sprintf("❌ BigDirectory doit avoir 2-32 enfants, a %d", len(childHashes)))
	}
	// Format: [Type (1 byte)] [Hash1 (32 bytes)] [Hash2 (32 bytes)] ...
	datum := make([]byte, 1+len(childHashes)*HashSize)
	datum[0] = TypeBigDirectory
	for i, h := range childHashes {
		copy(datum[1+i*HashSize:], h[:])
	}

	hash := HashData(datum)
	return datum, hash
}

// FileToMerkle convertit un fichier en arbre de Merkle et stocke les datums
func FileToMerkle(store *Store, filePath string) ([32]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()

	// Lire le fichier en chunks
	var chunkHashes [][32]byte
	buffer := make([]byte, MaxChunkSize)

	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return [32]byte{}, err
		}

		// Créer un chunk pour ces données
		datum, hash := CreateChunk(buffer[:n])
		store.Add(datum)
		chunkHashes = append(chunkHashes, hash)
	}

	// Si un seul chunk, retourner directement son hash
	if len(chunkHashes) == 0 {
		// Fichier vide
		datum, hash := CreateChunk([]byte{})
		store.Add(datum)
		return hash, nil
	}
	if len(chunkHashes) == 1 {
		return chunkHashes[0], nil
	}

	// Sinon, créer un arbre de Big nodes
	return buildBigTree(store, chunkHashes), nil
}

// buildBigTree construit récursivement un arbre de Big nodes
func buildBigTree(store *Store, hashes [][32]byte) [32]byte {
	if len(hashes) <= MaxBigChildren {
		if len(hashes) == 1 {
			return hashes[0]
		}
		datum, hash := CreateBigNode(hashes)
		store.Add(datum)
		return hash
	}

	// Diviser en groupes de MaxBigChildren
	var newHashes [][32]byte
	for i := 0; i < len(hashes); i += MaxBigChildren {
		end := i + MaxBigChildren
		if end > len(hashes) {
			end = len(hashes)
		}
		group := hashes[i:end]
		if len(group) == 1 {
			newHashes = append(newHashes, group[0])
		} else {
			datum, hash := CreateBigNode(group)
			store.Add(datum)
			newHashes = append(newHashes, hash)
		}
	}

	return buildBigTree(store, newHashes)
}

// MakeDirEntry crée une entrée de répertoire
func MakeDirEntry(name string, hash [32]byte) DirEntry {
	entry := DirEntry{Hash: hash}
	// Copier le nom (max 32 caractères, padded avec des 0)
	copy(entry.Name[:], []byte(name))
	return entry
}

// DirToMerkle convertit un répertoire en arbre de Merkle
func DirToMerkle(store *Store, dirPath string) ([32]byte, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return [32]byte{}, err
	}

	var dirEntries []DirEntry

	for _, entry := range entries {
		name := entry.Name()
		if len(name) > FileNameSize {
			name = name[:FileNameSize] // Tronquer si trop long
		}

		fullPath := filepath.Join(dirPath, entry.Name())

		var hash [32]byte
		if entry.IsDir() {
			hash, err = DirToMerkle(store, fullPath)
		} else {
			hash, err = FileToMerkle(store, fullPath)
		}
		if err != nil {
			return [32]byte{}, err
		}

		dirEntries = append(dirEntries, MakeDirEntry(name, hash))
	}

	// Si plus de 16 entrées, créer un BigDirectory
	if len(dirEntries) > MaxDirEntries {
		return buildBigDirectory(store, dirEntries), nil
	}

	// Sinon, créer un Directory simple
	datum, hash := CreateDirectoryNode(dirEntries)
	store.Add(datum)
	return hash, nil
}

// buildBigDirectory construit un BigDirectory pour les grands répertoires
func buildBigDirectory(store *Store, entries []DirEntry) [32]byte {
	var dirHashes [][32]byte

	// Créer des Directory nodes de 16 entrées max
	for i := 0; i < len(entries); i += MaxDirEntries {
		end := min(i + MaxDirEntries, len(entries))
		group := entries[i:end]
		datum, hash := CreateDirectoryNode(group)
		store.Add(datum)
		dirHashes = append(dirHashes, hash)
	}

	// Si un seul Directory, le retourner directement
	if len(dirHashes) == 1 {
		return dirHashes[0]
	}

	// Sinon, créer un arbre de BigDirectory
	return buildBigDirTree(store, dirHashes)
}

// buildBigDirTree construit récursivement un arbre de BigDirectory nodes
func buildBigDirTree(store *Store, hashes [][32]byte) [32]byte {
	if len(hashes) <= MaxBigChildren {
		if len(hashes) == 1 {
			return hashes[0]
		}
		datum, hash := CreateBigDirectoryNode(hashes)
		store.Add(datum)
		return hash
	}

	var newHashes [][32]byte
	for i := 0; i < len(hashes); i += MaxBigChildren {
		end := i + MaxBigChildren
		if end > len(hashes) {
			end = len(hashes)
		}
		group := hashes[i:end]
		if len(group) == 1 {
			newHashes = append(newHashes, group[0])
		} else {
			datum, hash := CreateBigDirectoryNode(group)
			store.Add(datum)
			newHashes = append(newHashes, hash)
		}
	}

	return buildBigDirTree(store, newHashes)
}

// ParseDatum analyse un datum et retourne son type et ses données
func ParseDatum(datum []byte) (uint8, []byte) {
	if len(datum) == 0 {
		return 0, nil
	}
	return datum[0], datum[1:]
}

// ParseDirectoryEntries extrait les entrées d'un datum Directory
func ParseDirectoryEntries(data []byte) []DirEntry {
	var entries []DirEntry
	for i := 0; i+DirEntrySize <= len(data); i += DirEntrySize {
		var entry DirEntry
		copy(entry.Name[:], data[i:i+FileNameSize])
		copy(entry.Hash[:], data[i+FileNameSize:i+DirEntrySize])
		entries = append(entries, entry)
	}
	return entries
}

// ParseBigHashes extrait les hashes d'un datum Big ou BigDirectory
func ParseBigHashes(data []byte) [][32]byte {
	var hashes [][32]byte
	for i := 0; i+HashSize <= len(data); i += HashSize {
		var hash [32]byte
		copy(hash[:], data[i:i+HashSize])
		hashes = append(hashes, hash)
	}
	return hashes
}

// GetEntryName retourne le nom d'une entrée (sans les octets nuls)
func GetEntryName(entry DirEntry) string {
	// Trouver le premier octet nul
	for i, b := range entry.Name {
		if b == 0 {
			return string(entry.Name[:i])
		}
	}
	return string(entry.Name[:])
}
