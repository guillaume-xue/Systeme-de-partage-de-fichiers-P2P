package merkle

// Types de nœuds définis dans le protocole [cite: 201]
const (
	TypeChunk        = 0 // Données brutes (<= 1024 octets)
	TypeDirectory    = 1 // Liste de fichiers (<= 16 entrées)
	TypeBig          = 3 // Fichier fragmenté (> 1024 octets)
	TypeBigDirectory = 4 // Répertoire fragmenté (> 16 entrées)
)

// Constantes de taille [cite: 195, 196, 197]
const (
	MaxChunkSize   = 1024
	MaxDirEntries  = 16
	MaxBigChildren = 32
	HashSize       = 32
	DirEntrySize   = 64 // 32 bytes nom + 32 bytes hash
)
