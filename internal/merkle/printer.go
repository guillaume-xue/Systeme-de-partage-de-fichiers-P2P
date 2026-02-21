package merkle

import (
	"fmt"
	"main/internal/utils"
)

// DatumProvider est une interface pour accéder aux datums Merkle,
// que ce soit depuis un Store local ou un cache de téléchargement.
type DatumProvider interface {
	Get(hash [32]byte) ([]byte, bool)
}

// PrintTree affiche récursivement l'arborescence d'un arbre Merkle.
func PrintTree(provider DatumProvider, hash [32]byte, prefix, fileName string, isLast bool) {
	datum, found := provider.Get(hash)

	marker := "├── "
	if isLast {
		marker = "└── "
	}

	if !found {
		fmt.Printf("%s%s [???] nom: %s (manquant) %x\n", prefix, marker, fileName, hash)
		return
	}
	nodeType, nodeData := ParseDatum(datum)

	newPrefix := prefix + "│   "
	if isLast {
		newPrefix = prefix + "    "
	}

	switch nodeType {
	case TypeDirectory:
		entries := ParseDirectoryEntries(nodeData)
		fmt.Printf("%s%s%s 📁 [DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			PrintTree(provider, e.Hash, newPrefix, GetEntryName(e), i == len(entries)-1)
		}
	case TypeBigDirectory:
		entries := ParseBigHashes(nodeData)
		fmt.Printf("%s%s%s 📁 [BIG-DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			PrintTree(provider, e, newPrefix, "", i == len(entries)-1)
		}
	case TypeChunk:
		fmt.Printf("%s%s%s 📄 [FILE] (%s) %x\n", prefix, marker, fileName, utils.FormatBytesInt64(int64(len(nodeData))), hash)

	case TypeBig:
		children := ParseBigHashes(nodeData)
		fmt.Printf("%s%s%s 📄 [BIG-FILE] (%d fragments) %x\n", prefix, marker, fileName, len(children), hash)
	}
}
