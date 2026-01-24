package merkle

func ParseDatum(datum []byte) (uint8, []byte) {
	if len(datum) == 0 {
		return 0, nil
	}
	return datum[0], datum[1:]
}

func ParseDirectoryEntries(data []byte) []DirEntry {
	count := len(data) / DirEntrySize
	entries := make([]DirEntry, count)
	for i := range count {
		start := i * DirEntrySize
		copy(entries[i].Name[:], data[start:start+FileNameSize])
		copy(entries[i].Hash[:], data[start+FileNameSize:start+DirEntrySize])
	}
	return entries
}

func ParseBigHashes(data []byte) [][32]byte {
	count := len(data) / HashSize
	hashes := make([][32]byte, count)
	for i := range count {
		copy(hashes[i][:], data[i*HashSize:(i+1)*HashSize])
	}
	return hashes
}

// Helper retourne le nom d'une entrée (sans les octets nuls)
func GetEntryName(e DirEntry) string {
	for i, b := range e.Name[:] {
		if b == 0 {
			return string(e.Name[:i])
		}
	}
	return string(e.Name[:])
}
