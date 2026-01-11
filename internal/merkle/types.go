package merkle

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// Types de nœuds définis dans le protocole [cite: 201]
const (
	TypeChunk        = 0 // Données brutes (<= 1024 octets)
	TypeDirectory    = 1 // Liste de fichiers (<= 16 entrées)
	TypeBig          = 2 // Fichier fragmenté (> 1024 octets)
	TypeBigDirectory = 3 // Répertoire fragmenté (> 16 entrées)
)

// Constantes de taille [cite: 195, 196, 197]
const (
	MaxChunkSize   = 1024
	MaxDirEntries  = 16
	MaxBigChildren = 32
	HashSize       = 32
	DirEntrySize   = 64 // 32 bytes nom + 32 bytes hash
)

type Merkle struct {
	node  map[string][]byte
	mutex sync.RWMutex
}

func NewMerkle() *Merkle {
	return &Merkle{
		node: make(map[string][]byte),
	}
}

func (m *Merkle) AddNode(data []byte) {
	m.mutex.Lock()
	hash := sha256.Sum256(data)
	name := fmt.Sprintf("%x", hash[:])
	m.node[name] = data
	defer m.mutex.Unlock()
}

func (m *Merkle) PrintAllNodes() {
	m.mutex.RLock()
	for name, data := range m.node {
		hex := sha256.Sum256(data)
		strHex := fmt.Sprintf("%x", hex[:])
		println("Node Name:", name, "Data: ", strHex)
	}
	defer m.mutex.RUnlock()
}

func (m *Merkle) GetNode(hash []byte) ([]byte, bool) {
	m.mutex.RLock()
	hashStr := fmt.Sprintf("%x", hash)
	data, exists := m.node[hashStr]
	defer m.mutex.RUnlock()
	return data, exists
}

func (m *Merkle) Clean() {
	m.mutex.Lock()
	m.node = make(map[string][]byte)
	defer m.mutex.Unlock()
}

func (m *Merkle) Empty() bool {
	m.mutex.RLock()
	empty := len(m.node) == 0
	defer m.mutex.RUnlock()
	return empty
}

func (m *Merkle) Count() int {
	m.mutex.RLock()
	count := len(m.node)
	defer m.mutex.RUnlock()
	return count
}
