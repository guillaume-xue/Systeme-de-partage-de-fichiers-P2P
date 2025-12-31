package main

import (
	"fmt"
	"main/internal/cli"
	"main/internal/crypto"
	"main/internal/merkle"
	"main/internal/protocol"
	"main/internal/transport"
	"os"
	"path/filepath"
	"time"
)

func main() {
	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║   Client P2P - Système de fichiers         ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Println()

	// 1. Charger ou générer la clé privée
	privKey, err := crypto.LoadOrGenerateKey(protocol.FILENAME)
	if err != nil {
		fmt.Printf("❌ Erreur fatale: impossible de charger la clé: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Clé privée chargée")

	// 2. S'enregistrer auprès du serveur HTTP (nécessaire avant la connexion UDP)
	fmt.Println("\n📡 Enregistrement sur le serveur central...")
	if err := transport.RegisterHTTP(privKey); err != nil {
		fmt.Printf("❌ Erreur fatale: impossible de s'enregistrer: %v\n", err)
		fmt.Println("   Vérifiez votre connexion Internet.")
		os.Exit(1)
	}
	fmt.Println("✅ Clé publique enregistrée sur le serveur HTTP")

	// 3. Connexion avec fallback automatique IPv6 → IPv4
	fmt.Println("\n🌐 Connexion au serveur UDP...")
	conn, serverAddr, err := transport.TryConnectWithFallback(protocol.MyName, privKey)
	if err != nil {
		fmt.Printf("\n❌ Erreur fatale: %v\n", err)
		fmt.Println("\n💡 Vérifiez que:")
		fmt.Println("   - Vous êtes connecté à Internet")
		fmt.Println("   - Le port 8080 n'est pas bloqué par un firewall")
		fmt.Println("   - Le serveur jch.irif.fr est accessible")
		os.Exit(1)
	}
	defer conn.Close()

	// Afficher le mode réseau utilisé
	fmt.Printf("🌐 Mode réseau: %s\n", transport.GetNetworkMode())

	// 4. Créer le serveur
	server := transport.NewServer(conn, privKey, protocol.MyName)

	// 5. Charger le dossier partagé dans le Merkle tree
	sharedDir := filepath.Join(".", "shared")
	store := merkle.NewStore()
	rootHash, err := merkle.DirToMerkle(store, sharedDir)
	if err != nil {
		fmt.Printf("⚠️ Erreur chargement dossier partagé: %v\n", err)
		fmt.Println("  Création d'un store vide...")
	} else {
		server.SetMerkleRoot(store, rootHash)
		fmt.Printf("✅ Dossier partagé chargé (root: %x...)\n", rootHash[:8])
		fmt.Printf("   %d datums dans le store\n", store.Len())
	}

	// 6. Démarrer l'écoute UDP
	go server.ListenLoop()
	fmt.Println("✅ Écoute UDP démarrée")

	// 7. Démarrer le keep-alive (Ping toutes les 3 minutes)
	go server.KeepAlive(serverAddr, 3*time.Minute)
	fmt.Println("✅ Keep-alive activé")

	fmt.Println("\n" + "═══════════════════════════════════════════")
	fmt.Println("🚀 Client démarré!")
	fmt.Printf("   Nom: %s\n", protocol.MyName)
	fmt.Printf("   Serveur: %s\n", serverAddr)
	fmt.Println("═══════════════════════════════════════════")

	// 8. Lancer l'interface CLI interactive
	cliInterface := cli.NewCLI(server, serverAddr)
	cliInterface.Run()
}
