package merkle

import (
	"bytes"
	"fmt"
	"strings"
)

type DirEntry struct {
	Name string
	Hash []byte
}

func (m *Merkle) ParseValue(value []byte) ([][]byte, error) {
	m.AddNode(value)
	fmt.Println("Parsing value of length:", len(value))
	fmt.Printf("Type de nœud : %d\n", value[0])
	switch value[0] {
	case TypeChunk:
		return nil, nil
	case TypeBig:
		return ParseBig(value[1:])
	case TypeDirectory:
		entries, err := ParseDirectory(value[1:])
		if err != nil {
			return nil, err
		}
		// Extraire juste les hash pour la compatibilité
		var hashes [][]byte
		for _, entry := range entries {
			hashes = append(hashes, entry.Hash)
		}
		return hashes, nil
	case TypeBigDirectory:
		return ParseBigDirectory(value[1:])
	default:
		return nil, fmt.Errorf("type de nœud inconnu: %d", value[0])
	}
}

func ParseBig(data []byte) ([][]byte, error) {
	var child [][]byte

	count := len(data) / 32

	for i := 0; i < count; i++ {
		start := i * 32
		end := start + 32
		child = append(child, data[start:end])
	}
	fmt.Printf("Chunk avec %d enfants\n", count)
	return child, nil
}

func ParseDirectory(data []byte) ([]DirEntry, error) {

	entries := len(data) / DirEntrySize

	var dirEntries []DirEntry
	for i := 0; i < entries; i++ {
		entry := data[i*DirEntrySize : (i+1)*DirEntrySize]
		nameBytes := entry[:32]
		name := string(bytes.TrimRight(nameBytes, "\x00"))
		name = strings.TrimSpace(name)
		hash := entry[32:64]
		fmt.Printf(" - Nom: %s, Hash: %x\n", name, hash)
		dirEntries = append(dirEntries, DirEntry{
			Name: name,
			Hash: hash,
		})
	}
	fmt.Printf("Directory avec %d entrées\n", entries)
	return dirEntries, nil
}

func ParseBigDirectory(data []byte) ([][]byte, error) {
	var dirs [][]byte

	count := len(data) / 32

	for i := 0; i < count; i++ {
		start := i * 32
		end := start + 32
		dirs = append(dirs, data[start:end])
	}
	fmt.Printf("BigDirectory avec %d enfants\n", count)
	return dirs, nil
}
