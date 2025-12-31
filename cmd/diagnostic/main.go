package main

import (
	"fmt"
	"main/internal/protocol"
	"main/internal/transport"
	"net/http"
	"os"
	"strings"
	"time"
)

// Outil de diagnostic pour analyser les problèmes de connexion

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: diagnostic <peer_name>")
		fmt.Println("Exemple: diagnostic jch")
		os.Exit(1)
	}

	peerName := os.Args[1]
	fmt.Printf("═══════════════════════════════════════════════════════\n")
	fmt.Printf("  DIAGNOSTIC DE CONNEXION POUR: %s\n", peerName)
	fmt.Printf("═══════════════════════════════════════════════════════\n\n")

	// 1. Vérifier si le peer existe sur le serveur
	fmt.Println("1️⃣  Vérification de l'existence sur le serveur REST...")
	peers, err := transport.GetListPeers()
	if err != nil {
		fmt.Printf("   ❌ Impossible de contacter le serveur: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, p := range peers {
		if strings.TrimSpace(p) == peerName {
			found = true
			break
		}
	}

	if found {
		fmt.Printf("   ✅ Le peer '%s' est enregistré sur le serveur\n", peerName)
	} else {
		fmt.Printf("   ❌ Le peer '%s' n'est PAS dans la liste des peers!\n", peerName)
		fmt.Println("   💡 Le peer doit d'abord s'enregistrer avec un Hello au serveur")
		os.Exit(1)
	}

	// 2. Récupérer la clé publique
	fmt.Println("\n2️⃣  Récupération de la clé publique...")
	keyBytes, err := transport.GetKey(peerName)
	if err != nil {
		fmt.Printf("   ❌ Impossible de récupérer la clé: %v\n", err)
		os.Exit(1)
	}

	if len(keyBytes) != 64 {
		fmt.Printf("   ❌ Clé invalide (taille=%d, attendu=64)\n", len(keyBytes))
		os.Exit(1)
	}
	fmt.Printf("   ✅ Clé publique récupérée (64 bytes)\n")
	fmt.Printf("      Clé: %x...\n", keyBytes[:16])

	// 3. Récupérer les adresses
	fmt.Println("\n3️⃣  Récupération des adresses UDP...")
	addrStr, err := transport.GetAddr(peerName)
	if err != nil {
		fmt.Printf("   ❌ Impossible de récupérer les adresses: %v\n", err)
		os.Exit(1)
	}

	addrStr = strings.TrimSpace(addrStr)
	if addrStr == "" {
		fmt.Println("   ❌ Aucune adresse enregistrée!")
		fmt.Println("   💡 Le peer est enregistré mais n'a pas d'adresse UDP")
		fmt.Println("      Causes possibles:")
		fmt.Println("      - Le peer n'a pas envoyé de Hello au serveur UDP")
		fmt.Println("      - Le serveur n'a pas pu vérifier l'adresse (HelloReply non reçu)")
		fmt.Println("      - Les adresses ont expiré (timeout serveur)")
		os.Exit(1)
	}

	addrs := strings.Split(addrStr, "\n")
	fmt.Printf("   ✅ %d adresse(s) trouvée(s):\n", len(addrs))
	for i, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		// Vérifier compatibilité
		canComm := transport.CanCommunicateWith(addr)
		isIPv6 := transport.IsIPv6Address(addr)
		status := "✅"
		if !canComm {
			status = "❌ (incompatible)"
		}
		ipType := "IPv4"
		if isIPv6 {
			ipType = "IPv6"
		}
		fmt.Printf("      %d. %s [%s] %s\n", i+1, addr, ipType, status)
	}

	// 4. Sélectionner la meilleure adresse
	fmt.Println("\n4️⃣  Sélection de l'adresse...")
	selectedAddr := transport.SelectBestAddress(addrs)
	if selectedAddr == "" {
		fmt.Println("   ❌ Aucune adresse compatible avec votre mode réseau!")
		fmt.Printf("   💡 Votre mode: %s\n", transport.GetNetworkMode())
		fmt.Println("      Le peer n'a peut-être qu'une adresse IPv6 et vous êtes en IPv4")
		os.Exit(1)
	}
	fmt.Printf("   ✅ Adresse sélectionnée: %s\n", selectedAddr)

	// 5. Analyse des causes possibles
	fmt.Println("\n5️⃣  ANALYSE DES CAUSES DE NON-RÉPONSE:")
	fmt.Println("   ─────────────────────────────────────────")
	fmt.Println("   Si vous envoyez un Hello mais ne recevez pas de HelloReply:")
	fmt.Println()
	fmt.Println("   A) PROBLÈME CÔTÉ PEER DISTANT:")
	fmt.Println("      • Le peer n'est pas en train d'écouter (programme fermé)")
	fmt.Println("      • Le peer est derrière un NAT strict")
	fmt.Println("      • Le peer n'a pas implémenté processHello correctement")
	fmt.Println()
	fmt.Println("   B) PROBLÈME RÉSEAU:")
	fmt.Println("      • Firewall bloque UDP sortant ou entrant")
	fmt.Println("      • NAT symétrique des deux côtés")
	fmt.Println("      • L'adresse publiée est obsolète")
	fmt.Println()
	fmt.Println("   C) PROBLÈME DE SIGNATURE:")
	fmt.Println("      • Votre clé publique n'est pas sur le serveur")
	fmt.Println("      • Signature mal formée")
	fmt.Println()

	// 6. Vérifier notre propre enregistrement
	fmt.Println("6️⃣  Vérification de VOTRE enregistrement...")
	myKeyBytes, err := transport.GetKey(protocol.MyName)
	if err != nil {
		fmt.Printf("   ⚠️  Votre clé (%s) n'est pas sur le serveur!\n", protocol.MyName)
		fmt.Println("      Le peer distant ne peut pas vérifier votre signature")
	} else if len(myKeyBytes) != 64 {
		fmt.Printf("   ⚠️  Votre clé est invalide (taille=%d)\n", len(myKeyBytes))
	} else {
		fmt.Printf("   ✅ Votre clé (%s) est sur le serveur\n", protocol.MyName)
	}

	myAddrStr, err := transport.GetAddr(protocol.MyName)
	if err != nil || strings.TrimSpace(myAddrStr) == "" {
		fmt.Printf("   ⚠️  Votre adresse UDP n'est pas publiée!\n")
		fmt.Println("      Le peer ne peut pas vous répondre directement")
	} else {
		fmt.Printf("   ✅ Votre adresse est publiée: %s\n", strings.TrimSpace(strings.Split(myAddrStr, "\n")[0]))
	}

	// 7. Test de connectivité HTTP (pour vérifier Internet)
	fmt.Println("\n7️⃣  Test de connectivité générale...")
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://jch.irif.fr:8443/peers/")
	if err != nil {
		fmt.Printf("   ❌ Pas de connexion au serveur: %v\n", err)
	} else {
		resp.Body.Close()
		fmt.Printf("   ✅ Serveur REST accessible (HTTP %d)\n", resp.StatusCode)
	}

	fmt.Println("\n═══════════════════════════════════════════════════════")
	fmt.Println("  FIN DU DIAGNOSTIC")
	fmt.Println("═══════════════════════════════════════════════════════")
}
