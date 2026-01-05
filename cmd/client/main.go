package main

import (
	"context"
	"fmt"
	"log"
	"main/internal/config"
	"main/internal/crypto"
	"main/internal/menu"
	"main/internal/merkle"
	"main/internal/transport"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	// Setup pour gérer CTRL+c
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Gestion des signaux système (SIGINT, SIGTERM)
	// Qui aurait cru que j'allait devoir réimplémenter ça après les cours de L2
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Canal pour récupérer le résultat de run()
	// On le met à 1 pour ne pas bloquer si le main quitte avant
	done := make(chan error, 1)

	// Lancement du programme principal
	go func() {
		// Le résultat de run (erreur ou nil) est envoyé dans le canal 'done'
		done <- run(ctx)
	}()

	// On attend soit un signal système, soit la fin du programme
	select {
	case sig := <-sigChan:
		// Cas A : L'utilisateur fait CTRL+C
		fmt.Printf("\n🛑 Signal reçu (%v), fermeture en cours...\n", sig)
		cancel() // On prévient run() qu'il faut arrêter via le contexte
	case err := <-done:
		// Cas B : Le menu est quitté ou une erreur critique survient
		if err != nil {
			log.Fatal("❌ Erreur critique : %w\n", err)
		}
		fmt.Println("\n✅ Application terminée normalement.")
	}
}

// run encapsule la logique pour permettre de 'defer' correctement
func run(ctx context.Context) error {
	fmt.Println("\n======= Client P2P - Système de fichiers =======")
	fmt.Println()

	// Chargement de la configuration
	cfg := config.LoadOrDefault("config.json")
	fmt.Printf("✅ Configuration chargée (Peer: %s)\n", cfg.Peer.Name)

	// Identité & Crypto
	privKey, err := crypto.LoadOrGenerateKey(cfg.Peer.KeyFile)
	if err != nil {
		return fmt.Errorf("❌ Impossible de charger la clé: %w", err)
	}
	fmt.Println("✅ Clé privée chargée")

	// Enregistrement HTTP
	if err := transport.RegisterHTTP(privKey); err != nil {
		return fmt.Errorf("❌ Impossible de s'enregistrer: %w\n", err)
	}
	fmt.Println("✅ Clé publique enregistrée sur le serveur HTTP")

	// Connexion UDP
	conn, serverAddr, err := transport.TryConnectWithFallback(cfg.Peer.Name, privKey)
	if err != nil {
		return fmt.Errorf("❌ Impossible de se connecter au serveur UDP: %w\n", err)
	}
	defer conn.Close()
	fmt.Printf("✅ Connecté au serveur UDP (%s) [Mode: %s]\n", serverAddr, transport.GetNetworkMode())

	// Initialisation du Serveur P2P
	server := transport.NewServer(conn, privKey, cfg.Peer.Name)

	// Charger le dossier partagé dans le Merkle tree ou la créer s'il n'existe pas
	sharedDir := filepath.Join(".", "shared")
	if _, err := os.Stat(sharedDir); os.IsNotExist(err) {
		if err := os.Mkdir(sharedDir, 0755); err != nil {
			return fmt.Errorf("❌ Impossible de créer le dossier partagé: %w\n", err)
		}
		fmt.Println("✅ Dossier partagé créé")
	}
	store := merkle.NewStore()
	rootHash, err := merkle.DirToMerkle(store, sharedDir)
	if err != nil {
		return fmt.Errorf("❌ Impossible de charger le dossier partagé: %w\n", err)
	} else {
		server.SetMerkleRoot(store, rootHash)
		fmt.Printf("✅ Dossier partagé chargé (root: %x...)\n", rootHash)
	}

	// Démarrage des services
	// Routine d'écoute
	go server.ListenLoop(ctx)
	fmt.Println("✅ Routine d'écoute UDP démarrée")

	// Routine keep-alive
	go server.KeepAlive(serverAddr, cfg.Network.KeepAlive, ctx)
	fmt.Printf("✅ Keep-alive activé (%v)\n", cfg.Network.KeepAlive)

	fmt.Println("\n✅ Client démarré!")
	fmt.Printf("   Nom: %s\n", cfg.Peer.Name)
	fmt.Printf("   Serveur: %s\n", serverAddr)

	// Interface Utilisateur
	interactiveMenu := menu.NewMenu(server, serverAddr)
	interactiveMenu.Run()

	return nil
}
