package main

import (
	"fmt"
	"main/internal/crypto"
	"main/internal/transport"
)

const (
	FILENAME      = "client_key.pem"
	ServerUDPAddr = "localhost:8080"
)

func main() {
	privKey, _ := crypto.LoadOrGenerateKey(FILENAME)

	if err := transport.RegisterHTTP(privKey); err != nil {
		fmt.Println("Erreur HTTP:", err)
	}

	listOfPeers, err := transport.GetListPeers()
	if err != nil {
		fmt.Println("Erreur lors de la récupération de la liste des pairs :", err)
		return
	}

	fmt.Println("Liste des pairs récupérée avec succès :")
	for _, peer := range listOfPeers {
		fmt.Println("-", peer)
	}

	get_key, err := transport.GetKey("Gui")
	if err != nil {
		fmt.Println("Erreur lors de la récupération de la clé du pair :", err)
		return
	}

	extracted_key := crypto.ParsePublicKey(get_key)
	bytes_key := crypto.PublicKeyToBytes(extracted_key)
	fmt.Println("Clé publique récupérée du pair Gui :", bytes_key)
}
