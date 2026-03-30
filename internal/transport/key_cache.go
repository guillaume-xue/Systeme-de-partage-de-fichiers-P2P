package transport

import "main/internal/utils"

// KeyCache est un cache thread-safe pour les clés publiques des peers.
// Évite de spammer l'annuaire HTTP à chaque vérification de signature.
// Utilise SafeMap générique pour éviter la duplication de code.
type KeyCache = utils.SafeMap[string, []byte]

func NewKeyCache() *KeyCache {
	return utils.NewSafeMap[string, []byte]()
}
