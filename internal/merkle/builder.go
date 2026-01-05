package merkle

import (
	"fmt"
)

func (m *Merkle) ParseValue(value []byte) ([][]byte, error) {
	m.AddNode(value)
	fmt.Println("Parsing value of length:", len(value))
	fmt.Printf("Type de nœud : %d\n", value[0])
	switch value[0] {
	case TypeChunk:
		return nil, nil
	case TypeBig:
		return m.ParseChunk(value[1:])
	case TypeDirectory:
		return m.ParseDirectory(value[1:])
	case TypeBigDirectory:
		return m.ParseBigDirectory(value[1:])
	default:
		return nil, fmt.Errorf("type de nœud inconnu: %d", value[0])
	}
}

func (m *Merkle) ParseChunk(data []byte) ([][]byte, error) {
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

func (m *Merkle) ParseDirectory(data []byte) ([][]byte, error) {

	entries := len(data) / DirEntrySize

	var dirs [][]byte
	for i := 0; i < entries; i++ {
		entry := data[i*DirEntrySize : (i+1)*DirEntrySize]
		fmt.Printf(" - Nom: %s, Hash: %x\n", string(entry[:32]), entry[32:])
		dirs = append(dirs, entry[32:])
	}
	fmt.Printf("Directory avec %d entrées\n", entries)
	return dirs, nil
}

func (m *Merkle) ParseBigDirectory(data []byte) ([][]byte, error) {
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
