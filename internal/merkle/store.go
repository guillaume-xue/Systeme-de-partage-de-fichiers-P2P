package merkle

import "main/internal/utils"

// Store est le stockage thread-safe des datums Merkle.
// Utilise SafeMap générique pour éviter la duplication de code.
type Store = utils.SafeMap[[32]byte, []byte]

func NewStore() *Store {
	return utils.NewSafeMap[[32]byte, []byte]()
}
