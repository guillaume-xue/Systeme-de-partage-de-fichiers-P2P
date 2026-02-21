package utils

import "sync"

// SafeMap est un cache thread-safe générique.
// Remplace les patterns répétés de map + RWMutex + Get/Set.
type SafeMap[K comparable, V any] struct {
	data map[K]V
	mu   sync.RWMutex
}

func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{
		data: make(map[K]V),
	}
}

func (m *SafeMap[K, V]) Set(key K, value V) {
	m.mu.Lock()
	m.data[key] = value
	m.mu.Unlock()
}

func (m *SafeMap[K, V]) Get(key K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[key]
	return val, ok
}

func (m *SafeMap[K, V]) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}
