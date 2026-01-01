package main

import (
	"fmt"
	"main/internal/crypto"
	"main/internal/menu"
	"main/internal/merkle"
	"main/internal/protocol"
	"main/internal/transport"
	"os"
	"path/filepath"
	"time"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════╗")
	fmt.Println("║   	 Client P2P - Système de fichiers       ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")
	fmt.Println()

	// 1. Charger ou générer la clé privée
	fmt.Println("🔑 Chargement de la clé privée...")
	privKey, err := crypto.LoadOrGenerateKey(protocol.FILENAME)
	if err != nil {
		fmt.Printf("❌ Impossible de charger la clé: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Clé privée chargée")

	// 2. S'enregistrer auprès du serveur HTTP (nécessaire avant la connexion UDP)
	fmt.Println("\n🌍 Enregistrement auprès du serveur HTTP...")
	if err := transport.RegisterHTTP(privKey); err != nil {
		fmt.Printf("❌ Impossible de s'enregistrer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Clé publique enregistrée sur le serveur HTTP")

	// 3. Connexion avec fallback automatique IPv6 → IPv4
	fmt.Println("\n🌐 Connexion au serveur UDP...")
	conn, serverAddr, err := transport.TryConnectWithFallback(protocol.MyName, privKey)
	if err != nil {
		fmt.Printf("❌ Impossible de se connecter au serveur UDP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("✅ Connecté au serveur UDP (%s)\n", serverAddr)

	// Afficher le mode réseau utilisé
	fmt.Printf("🌐 Mode réseau: %s\n", transport.GetNetworkMode())

	// 4. Créer le serveur
	server := transport.NewServer(conn, privKey, protocol.MyName)

	// 4.1 Ajouter le serveur central comme peer associé automatiquement
	// Cela évite de devoir se réassocier manuellement après une déconnexion récente
	server.AddServerAsPeer(serverAddr, "jch.irif.fr")

	// 5. Charger le dossier partagé dans le Merkle tree ou la créer s'il n'existe pas
	sharedDir := filepath.Join(".", "shared")
	if _, err := os.Stat(sharedDir); os.IsNotExist(err) {
		fmt.Println("ℹ️  Dossier partagé 'shared/' inexistant, création...")
		if err := os.Mkdir(sharedDir, 0755); err != nil {
			fmt.Printf("❌ Impossible de créer le dossier partagé: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Dossier partagé créé")
	}
	store := merkle.NewStore()
	rootHash, err := merkle.DirToMerkle(store, sharedDir)
	if err != nil {
		fmt.Printf("❌ Impossible de charger le dossier partagé: %v\n", err)
		os.Exit(1)
	} else {
		server.SetMerkleRoot(store, rootHash)
		fmt.Printf("✅ Dossier partagé chargé (root: %x...)\n", rootHash)
		fmt.Printf("   %d datums dans le store\n", store.Len())
	}

	// 6. Démarrer l'écoute UDP
	go server.ListenLoop()
	fmt.Println("✅ Écoute UDP démarrée")

	// 7. Démarrer le keep-alive (Ping toutes les 3 minutes)
	go server.KeepAlive(serverAddr, 3*time.Minute)
	fmt.Println("✅ Keep-alive activé")

	fmt.Println("\n" + "══════════════════════════════════════════════════")
	fmt.Println("🆙 Client démarré!")
	fmt.Printf("   Nom: %s\n", protocol.MyName)
	fmt.Printf("   Serveur: %s\n", serverAddr)
	fmt.Println("══════════════════════════════════════════════════")

	// 8. Lancer l'interface menu interactive
	interactiveMenu := menu.NewMenu(server, serverAddr)
	interactiveMenu.Run()
}
