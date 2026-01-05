package main

import (
	"log"
	"main/internal/transport"
	"os"
)

func main() {
	// Créer/ouvrir le fichier de log
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Erreur lors de la création du fichier log:", err)
	}
	defer logFile.Close()

	// Rediriger stdout et stderr vers le fichier
	os.Stdout = logFile
	os.Stderr = logFile

	transport.RunServerUDP()
}
