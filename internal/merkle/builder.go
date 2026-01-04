package merkle

import "fmt"

func ParseValue(value []byte) (string, error) {
	fmt.Println("Parsing value of length:", len(value))
	fmt.Printf("Type de nœud : %d\n", value[0])
	switch value[0] {
	case TypeChunk:
	case TypeDirectory:
		fmt.Println("Parsing directory...")
		return ParseDirectory(value[1:])
	case TypeBig:
	case TypeBigDirectory:
	default:
		return "", nil
	}
	return "", nil
}

func ParseDirectory(data []byte) (string, error) {
	if len(data)%DirEntrySize != 0 {
		return "", nil
	}
	entries := len(data) / DirEntrySize
	if entries > MaxDirEntries {
		return "", nil
	}
	var names string
	for i := 0; i < entries; i++ {
		entry := data[i*DirEntrySize : (i+1)*DirEntrySize]
		name := entry[:32]
		names += string(name)
		names += " "
	}
	fmt.Printf("Noms des entrées du répertoire : %s\n", names)
	return names, nil
}
