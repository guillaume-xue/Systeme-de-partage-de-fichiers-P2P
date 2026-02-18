package transport

import (
	"sync"
	"sync/atomic"
)

type DatumHandler func(hash [32]byte, data []byte)
type DatumDispatcher struct {
	subscribers map[int64]DatumHandler // On utilise un ID int
	mu          sync.RWMutex
	counter     int64 // Compteur auto-incrémenté pour les IDs
}

func NewDatumDispatcher() *DatumDispatcher {
	return &DatumDispatcher{
		subscribers: make(map[int64]DatumHandler),
	}
}

// Subscribe ajoute un écouteur
// name est là pour le debug, on ne s'en sert pas pour la logique interne
// Retourne une fonction "unsubscribe" à appeler pour nettoyer
func (d *DatumDispatcher) Subscribe(name string, handler DatumHandler) func() {
	d.mu.Lock()
	defer d.mu.Unlock()

	id := atomic.AddInt64(&d.counter, 1)
	d.subscribers[id] = handler

	return func() {
		d.remove(id)
	}
}

func (d *DatumDispatcher) remove(id int64) {
	d.mu.Lock()
	delete(d.subscribers, id)
	d.mu.Unlock()
}

// Dispatch envoie la donnée à tous les subscribers (appel synchrone)
func (d *DatumDispatcher) Dispatch(hash [32]byte, datum []byte) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, handler := range d.subscribers {
		handler(hash, datum)
	}
}
