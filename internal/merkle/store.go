package merkle

import (
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
