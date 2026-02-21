package menu

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"main/internal/config"
	"main/internal/merkle"
	"main/internal/peer"
	"main/internal/protocol"
	"main/internal/transport"
	"main/internal/utils"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

/*
	Structure et fonctions du menu interactif
*/

type InteractiveMenu struct {
	server     *transport.Server
	serverAddr *net.UDPAddr
	scanner    *bufio.Scanner
	hasIPv4    bool
	hasIPv6    bool
}

func NewMenu(server *transport.Server, serverAddr *net.UDPAddr) *InteractiveMenu {
	// Détecter les protocols ip supportés
	hasIPv4, hasIPv6 := utils.DetectLocalIPProtocol()
	scanner := bufio.NewScanner(os.Stdin)
	return &InteractiveMenu{
		server:     server,
		serverAddr: serverAddr,
		scanner:    scanner,
		hasIPv4:    hasIPv4,
		hasIPv6:    hasIPv6,
	}
}

// Run démarre la boucle principale du menu interactif
func (m *InteractiveMenu) Run(ctx context.Context) {
	fmt.Println("\n==========================================")
	fmt.Printf("   	   CLIENT P2P : %s\n", config.GlobalConfig.Peer.Name)
	fmt.Println("==========================================")

	for {
		fmt.Println("\n	--- MENU ---")
		fmt.Println("1. Peers disponibles")
		fmt.Println("2. Explorer fichiers distants")
		fmt.Println("3. Télécharger un fichier")
		fmt.Println("4. État des connexions")
		fmt.Println("5. Mes fichiers")
		fmt.Println("6. Activer le mode debug (afficher les datums)")
		if protocol.DebugEnabled {
			fmt.Println("7. Connexion manuelle")
		}
		fmt.Println("0. Quitter")

		choice := m.ask("\n> Choix : ")

		switch choice {
		case "1":
			m.listDirectoryPeers(false, false, ctx) // Juste liste, pas d'exploration ni téléchargement
		case "2":
			m.listDirectoryPeers(true, false, ctx) // Exploration en mémoire (pas de sauvegarde sur disque)
		case "3":
			m.listDirectoryPeers(true, true, ctx) // Téléchargement sur disque
		case "4":
			m.showConnections()
		case "5":
			m.showLocalFiles()
		case "6":
			protocol.DebugEnabled = !protocol.DebugEnabled
			fmt.Printf("ℹ️️ Mode debug : %v\n", protocol.DebugEnabled)
		case "7":
			if protocol.DebugEnabled {
				pName := m.ask("Nom du peer cible : ")
				m.connectToPeer(pName)
			}
		case "0", "q":
			m.server.Stop()
			return
		default:
			fmt.Println("⚠️ Choix invalide")
		}
	}
}

// 1. Lister les peers
func (m *InteractiveMenu) listDirectoryPeers(browseMode, diskCache bool, ctx context.Context) {
	fmt.Println("Récupération liste...")
	peers, err := transport.GetListPeers()
	if err != nil {
		fmt.Printf("Erreur HTTP: %v\n", err)
		return
	}
	if len(peers) == 0 {
		fmt.Println("Aucun peer trouvé dans la liste.")
		return
	}

	for i, p := range peers {
		fmt.Printf(" [%d] %s\n", i+1, p)
	}

	if !browseMode {
		m.waitKey()
		return
	}

	pName := m.ask("Nom du peer cible / numéro : ")
	if pName == "" {
		fmt.Println("Nom de peer vide")
		return
	}

	// Support choix par index
	if pIndex, err := strconv.Atoi(pName); err == nil && pIndex > 0 && pIndex <= len(peers) {
		pName = peers[pIndex-1]
	}

	pInfo, ok := m.server.Manager.Get(pName)
	if !ok {
		m.connectToPeer(pName)
		pInfo, _ = m.server.Manager.Get(pName)
	}

	if diskCache {
		m.downloadManual(pName, pInfo, ctx)
	} else {
		m.explorePeer(pName, pInfo)
	}

}

// 2. Explorer
func (m *InteractiveMenu) explorePeer(pName string, pInfo *peer.PeerInfo) {
	if pInfo == nil {
		return
	}

	fmt.Println("\n--- Mode d'exploration ---")
	fmt.Println("  Appuyez sur Entrée pour explorer depuis la racine (root)")
	fmt.Println("  Entrez un hash hex pour explorer depuis ce hash")
	fmt.Println("  Entrez un chemin (ex: dir/subdir, ./pictures) pour naviguer par nom")
	input := m.ask("Cible : ")

	targetHash, ok := m.resolveTarget(input, pInfo, pName)
	if !ok {
		return
	}

	// Extraire le nom d'affichage depuis le chemin (dernier composant)
	displayName := ""
	if input != "" && input != "root" && !looksLikeHash(input) {
		clean := strings.TrimRight(input, "/")
		if idx := strings.LastIndex(clean, "/"); idx >= 0 {
			displayName = clean[idx+1:]
		} else {
			displayName = clean
		}
	}

	// On télécharge l'arborescence depuis le hash cible
	fmt.Println("\nℹ️ Téléchargement de l'arborescence en cours...")
	dl := transport.NewDownloader(m.server, pInfo.GetAddr())
	dl.DownloadTree(targetHash)

	fmt.Println("\n--- ARBORESCENCE DISTANTE ---")
	merkle.PrintTree(m.server.Downloads, targetHash, "", displayName, true)
	m.waitKey()
}

// 3. Téléchargement via hash ou chemin
func (m *InteractiveMenu) downloadManual(pName string, pInfo *peer.PeerInfo, ctx context.Context) {
	if pInfo == nil {
		return
	}

	fmt.Println("\n--- Mode de téléchargement ---")
	fmt.Println("  Appuyez sur Entrée pour télécharger depuis la racine")
	fmt.Println("  Entrez un hash hex pour télécharger depuis ce hash")
	fmt.Println("  Entrez un chemin (ex: dir/subdir, ./pictures) pour naviguer par nom")
	input := m.ask("Cible : ")

	targetHash, ok := m.resolveTarget(input, pInfo, pName)
	if !ok {
		return
	}

	// Gestion Ctrl+C
	dlCtx, cancel := context.WithTimeout(ctx, config.GlobalConfig.Network.DownloadTimeout)
	defer cancel()

	destDir := filepath.Join("downloads", utils.CleanName(pName))
	fmt.Printf("ℹ️️ Destination: %s\n", destDir)
	diskDownloader := transport.NewDiskDownloader(m.server, pInfo.GetAddr(), destDir)
	if err := diskDownloader.DownloadToDisk(dlCtx, targetHash); err != nil {
		fmt.Printf("❌ Erreur lors du téléchargement: %v\n", err)
	}
	m.waitKey()
}

// 4. Affichage des connexions
func (m *InteractiveMenu) showConnections() {
	connectedPeers := m.server.Manager.List()

	fmt.Println("\nℹ️️ Peers connectés:")

	if len(connectedPeers) == 0 {
		fmt.Println("	Aucun peer connecté")
	} else {
		for _, pName := range connectedPeers {
			info, _ := m.server.Manager.Get(pName)
			fmt.Printf("\n  - %s\n", pName)
			for i, addrInfo := range info.Addrs {
				fmt.Printf("	Adresse %d: %s\n", i+1, addrInfo.Addr)
			}
			fmt.Printf("    Dernière activité: %s\n", info.LastSeen.Format("15:04:05"))
			if info.IsRelay {
				fmt.Println("    ℹ️️ Peut être utilisé comme relais NAT traversal")
			} else {
				fmt.Println("    ⚠️ Ne peut pas être utilisé comme relais NAT traversal")
			}
		}
	}
	m.waitKey()
}

// 5. Affichage des fichiers locaux
func (m *InteractiveMenu) showLocalFiles() {
	if m.server.RootHash == [32]byte{} {
		fmt.Println("\nℹ️️ Aucun fichier partagé")
		return
	}

	fmt.Println("\nℹ️️ Mes fichiers partagés:")
	fmt.Printf("  Hash racine: %x\n", m.server.RootHash)
	fmt.Printf("  Datums dans le store: %d\n", m.server.MerkleStore.Len())

	fmt.Println("\n  Arborescence:")
	merkle.PrintTree(m.server.MerkleStore, m.server.RootHash, "  ", "", true)

	m.waitKey()
}

// ask pose une question et retourne la réponse
func (m *InteractiveMenu) ask(question string) string {
	fmt.Print(question)
	m.scanner.Scan()
	fmt.Println()
	return strings.TrimSpace(m.scanner.Text())
}

// waitKey fait une pause simple
func (m *InteractiveMenu) waitKey() {
	fmt.Print("\n[Entrée pour continuer]")
	m.scanner.Scan()
}

// resolveTarget résout une cible (vide=root, hash hex, ou chemin) vers un hash Merkle.
// Retourne le hash et true si succès, ou [32]byte{} et false si erreur.
func (m *InteractiveMenu) resolveTarget(input string, pInfo *peer.PeerInfo, pName string) ([32]byte, bool) {
	input = strings.TrimSpace(input)
	peerAddr := pInfo.GetAddr()

	if input == "" {
		hash := m.getRootHashFromPeer(pInfo, pName)
		return hash, hash != [32]byte{}
	}

	if looksLikeHash(input) {
		parsed, err := utils.ParseHash(input)
		if err != nil {
			fmt.Printf("⚠️ Hash invalide : %v\n", err)
			return [32]byte{}, false
		}
		return parsed, true
	}

	// Résolution lazy par chemin
	rootHash := m.getRootHashFromPeer(pInfo, pName)
	if rootHash == ([32]byte{}) {
		return [32]byte{}, false
	}

	fmt.Printf("ℹ️️ Résolution du chemin '%s'...\n", input)
	fetcher := func(hash [32]byte) ([]byte, error) {
		return m.server.FetchDatum(peerAddr, hash, config.GlobalConfig.Network.ResolveDatumTimeout)
	}
	resolved, err := merkle.ResolvePathLazy(fetcher, rootHash, input)
	if err != nil {
		fmt.Printf("⚠️ Chemin introuvable : %v\n", err)
		m.waitKey()
		return [32]byte{}, false
	}
	fmt.Printf("✅ Chemin résolu : %s -> %x\n", input, resolved)
	return resolved, true
}

// getRootHashFromPeer demande et attend le hash racine depuis un peer
func (m *InteractiveMenu) getRootHashFromPeer(pInfo *peer.PeerInfo, pName string) [32]byte {
	fmt.Printf("ℹ️️ Demande du hash racine à %s...\n", pName)
	rootHashChan := make(chan [32]byte, 1)
	m.server.SetRootHashChan(rootHashChan)
	peerAddr := pInfo.GetAddr()
	m.server.Pending.RegisterRoot(peerAddr)
	transport.SendRootRequest(m.server.Conn, peerAddr)

	fmt.Println("ℹ️️ En attente de la réponse...")

	var targetHash [32]byte
	select {
	case tmpHash := <-rootHashChan:
		fmt.Println("✅ Réception du hash racine réussie")
		targetHash = tmpHash
		m.server.Pending.UnregisterRoot(peerAddr)
	case <-time.After(config.GlobalConfig.Network.RootReplyTimeout):
		fmt.Printf("⚠️ Timeout: pas de réponse reçue (%v)\n", config.GlobalConfig.Network.RootReplyTimeout)
		m.server.Pending.UnregisterRoot(peerAddr)
	}

	m.server.SetRootHashChan(nil)
	return targetHash
}

// looksLikeHash vérifie si une chaîne ressemble à un hash hexadécimal (au moins 16 chars hex)
func looksLikeHash(s string) bool {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s) < 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
