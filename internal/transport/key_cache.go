package transport

import "sync"

// KeyCache est un cache thread-safe pour les clés publiques des peers.
// Évite de spammer l'annuaire HTTP à chaque vérification de signature.
type KeyCache struct {
	cache map[string][]byte
	mu    sync.RWMutex
}

func NewKeyCache() *KeyCache {
	return &KeyCache{
		cache: make(map[string][]byte),
	}
}

// Get récupère une clé depuis le cache. Retourne nil, false si absente.
func (kc *KeyCache) Get(name string) ([]byte, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	k, ok := kc.cache[name]
	return k, ok
}

// Set ajoute ou met à jour une clé dans le cache.
func (kc *KeyCache) Set(name string, key []byte) {
	kc.mu.Lock()
	kc.cache[name] = key
	kc.mu.Unlock()
}
