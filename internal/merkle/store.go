package merkle

import (
	"crypto/sha256"
	"sync"
)

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
