package menu

import (
	"bufio"
	"context"
	"fmt"
	"main/internal/config"
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
	server       *transport.Server
	serverAddr   *net.UDPAddr
	scanner      *bufio.Scanner
	rootHashChan chan [32]byte
	hasIPv4      bool
	hasIPv6      bool
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
		fmt.Println("2. Connexion à un peer")
		fmt.Println("3. Explorer fichiers distants")
		fmt.Println("4. Télécharger un fichier")
		fmt.Println("5. État des connexions")
		fmt.Println("6. Mes fichiers")
		fmt.Println("7. Activer le mode debug (afficher les datums)")
		fmt.Println("0. Quitter")

		choice := m.ask("\n> Choix : ")

		switch choice {
		case "1":
			m.listDirectoryPeers()
		case "2":
			m.connectToPeer()
		case "3":
			m.explorePeer()
		case "4":
			m.downloadManual(ctx)
		case "5":
			m.showConnections()
		case "6":
			m.showLocalFiles()
		case "7":
			protocol.Debug_Enable = !protocol.Debug_Enable
			fmt.Printf("🔧 Mode debug (affichage datums) : %v\n", protocol.Debug_Enable)
		case "0", "q":
			m.server.Stop()
			return
		default:
			fmt.Println("❌ Choix invalide")
		}
	}
}

// 1. Lister les peers
func (m *InteractiveMenu) listDirectoryPeers() {
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
	m.waitKey()
}

// 2. Se connecter à un pair (Direct + NAT Traversal)
func (m *InteractiveMenu) connectToPeer() {
	pName := m.ask("Nom du peer cible : ")
	if pName == "" {
		fmt.Println("Nom de peer vide")
		return
	}
	// Récup ip, parser et filtrer
	listAddr, err := transport.GetAddr(pName)
	if err != nil {
		fmt.Printf("Impossible de récupérer les adresses de %s: %v\n", pName, err)
		return
	}
	targets := utils.AddrParserSolver(listAddr)
	if len(targets) == 0 {
		fmt.Println("Pas d'adresses valides trouvées.")
		return
	}
	targets = m.filterAddressesByProtocol(targets)
	if len(targets) == 0 {
		fmt.Println("Aucune adresse compatible avec nos protocols IP.")
		return
	}

	fmt.Println("Tentative de connexion...")
	// Phase 1: Tentatives de connexion directe
	m.sendDirectConnection(targets, pName, 1)

	// Vérifier quels protocoles ont réussi
	targetIPv4, targetIPv6 := utils.SeperateAddressesByProtocol(targets)
	var remainingTargets []*net.UDPAddr

	peerInfo, exists := m.server.PeerManager.Get(pName)
	if exists {
		// Vérifier quels protocoles manquent
		hasIPv4, hasIPv6 := false, false
		for _, addrInfo := range peerInfo.Addrs {
			if addrInfo.Addr.IP.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}

		// Garder uniquement les protocoles qui ont échoué
		if !hasIPv4 {
			remainingTargets = append(remainingTargets, targetIPv4...)
		}
		if !hasIPv6 {
			remainingTargets = append(remainingTargets, targetIPv6...)
		}
	} else {
		// Aucun protocole n'a réussi
		remainingTargets = targets
	}

	// Phase 2: NAT traversal pour les protocoles qui ont échoué
	if len(remainingTargets) > 0 {
		fmt.Println("\n--- Choix du relais pour NAT traversal ---")
		fmt.Println("Appuyez sur Entrée (ou tapez 'default') pour utiliser le serveur central")
		fmt.Println("Ou entrez le nom d'un peer connecté pour l'utiliser comme relais")
		choixRelais := m.ask("Relais : ")
		choixRelais = strings.TrimSpace(choixRelais)

		// Configurer les canaux de réception pour chaque adresse restante
		responseChan := make(chan *net.UDPAddr, max(len(remainingTargets)*2, 10))
		m.server.PingResponseMu.Lock()
		for _, target := range remainingTargets {
			m.server.PingResponseChans[target.String()] = responseChan
		}
		m.server.PingResponseMu.Unlock()

		if choixRelais == "" || choixRelais == "default" {
			choixRelais = "jch.irif.fr"
		}
		fmt.Printf("--- Tentative NAT traversal via %s... ---\n", choixRelais)
		natPerce := m.sendNatTraversalViaPeer(remainingTargets, choixRelais, responseChan)

		// Cleanup des canaux
		m.server.PingResponseMu.Lock()
		for _, target := range remainingTargets {
			delete(m.server.PingResponseChans, target.String())
		}
		m.server.PingResponseMu.Unlock()

		// Si le NAT est percé, tenter la connexion avec Hello sur les adresses qui ont fonctionné
		if natPerce {
			m.sendDirectConnection(remainingTargets, pName, 1)
		}
	}

	// Vérifier le résultat final
	peerInfo, exists = m.server.PeerManager.Get(pName)
	if exists {
		fmt.Printf("✅ SUCCÈS : Connecté à %s avec %d adresse(s) !\n", pName, len(peerInfo.Addrs))
	} else {
		fmt.Println("❌ ÉCHEC : Impossible de joindre le peer.")
	}
	m.waitKey()
}

// 3. Explorer
func (m *InteractiveMenu) explorePeer() {
	pInfo, pName := m.pickConnectedPeer()
	if pInfo == nil {
		return
	}
	targetHash := m.getRootHashFromPeer(pInfo, pName)
	if targetHash == ([32]byte{}) {
		return
	}

	// On télécharge uniquement la structure de l'arborescence
	fmt.Println("\n📥 Téléchargement de l'arborescence en cours...")
	dl := transport.NewDownloader(m.server, pInfo.GetAddr())
	dl.DownloadTree(targetHash)

	fmt.Println("\n--- ARBORESCENCE DISTANTE ---")
	utils.PrintTree(m.server.Downloads, targetHash, "", "", true)
	m.waitKey()
}

// 4. Téléchargement via hash
func (m *InteractiveMenu) downloadManual(ctx context.Context) {
	pInfo, pName := m.pickConnectedPeer()
	if pInfo == nil {
		return
	}

	hashInput := m.ask("Hash du datum (hex, ou 'root' pour la racine): ")

	var targetHash [32]byte
	if hashInput == "root" {
		targetHash = m.getRootHashFromPeer(pInfo, pName)
		if targetHash == ([32]byte{}) {
			return
		}
	} else {
		parsedHash, err := utils.ParseHash(hashInput)
		if err != nil {
			return
		}
		targetHash = parsedHash
	}
	// Gestion Ctrl+C
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	destDir := filepath.Join("downloads", utils.CleanName(pName))
	fmt.Printf("📂 Destination: %s\n", destDir)
	diskDownloader := transport.NewDiskDownloader(m.server, pInfo.GetAddr(), destDir)
	if err := diskDownloader.DownloadToDisk(dlCtx, targetHash); err != nil {
		fmt.Printf("❌ Erreur lors du téléchargement: %v\n", err)
	}
	m.waitKey()
}

// 5. Affichage des connexions
func (m *InteractiveMenu) showConnections() {
	connectedPeers := m.server.PeerManager.List()

	fmt.Println("\n🔗 Peers connectés:")

	if len(connectedPeers) == 0 {
		fmt.Println("	Aucun peer connecté")
	} else {
		for _, pName := range connectedPeers {
			info, _ := m.server.PeerManager.Get(pName)
			fmt.Printf("\n  - %s\n", pName)
			for i, addrInfo := range info.Addrs {
				fmt.Printf("	Adresse %d: %s\n", i+1, addrInfo.Addr)
			}
			fmt.Printf("    Dernière activité: %s\n", info.LastSeen.Format("15:04:05"))
			if info.IsRelay {
				fmt.Println("    🔄 Peut être utilisé comme relais NAT traversal")
			} else {
				fmt.Println("    ❌ Ne peut pas être utilisé comme relais NAT traversal")
			}
		}
	}
	m.waitKey()
}

// 6. Affichage des fichiers locaux
func (m *InteractiveMenu) showLocalFiles() {
	if m.server.RootHash == [32]byte{} {
		fmt.Println("\n📁 Aucun fichier partagé")
		return
	}

	fmt.Println("\n📁 Mes fichiers partagés:")
	fmt.Printf("  Hash racine: %x\n", m.server.RootHash)
	fmt.Printf("  Datums dans le store: %d\n", m.server.MerkleStore.Len())

	fmt.Println("\n  Arborescence:")
	utils.PrintTree(m.server.MerkleStore, m.server.RootHash, "  ", "", true)

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

// Envoie des Hello pour tenter une connexion directe
func (m *InteractiveMenu) sendDirectConnection(addresses []*net.UDPAddr, pName string, maxAttempts int) bool {
	startTime := time.Now()

	for range maxAttempts {
		for _, addr := range addresses {
			transport.SendHello(m.server.Conn, addr, m.server.MyName, m.server.PrivKey)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Vérifier si le peer existe et a été vu récemment
	if peerInfo, exists := m.server.PeerManager.Get(pName); exists {
		if peerInfo.LastSeen.After(startTime) {
			return true
		}
	}
	return false
}

// sendNatTraversalViaPeer utilise un pair comme relais pour le NAT traversal
func (m *InteractiveMenu) sendNatTraversalViaPeer(targetAddresses []*net.UDPAddr, relayPeerName string, responseChan chan *net.UDPAddr) bool {
	// Vérifier que le peer relais est connecté
	relayPeer, exists := m.server.PeerManager.Get(relayPeerName)
	if !exists {
		fmt.Printf("❌ Peer relais %s non connecté. Vous devez d'abord être connecté avec ce peer.\n", relayPeerName)
		return false
	}
	// Vérifier que le peer relais est configuré comme relais NAT
	if !relayPeer.IsRelay {
		fmt.Printf("❌ Peer relais %s n'est pas configuré comme relais NAT.\n", relayPeerName)
		return false
	}
	fmt.Printf("🚀 Utilisation de %s comme relais (%d adresse(s))\n", relayPeerName, len(relayPeer.Addrs))

	// Filtrer les adresses en fonction de nos protocols
	filteredTargets := m.filterAddressesByProtocol(targetAddresses)
	if len(filteredTargets) == 0 {
		fmt.Println("❌ Aucune adresse cible compatible avec nos protocols IP.")
		return false
	}

	targetIPv4, targetIPv6 := utils.SeperateAddressesByProtocol(filteredTargets)
	relayAddrs := make([]*net.UDPAddr, 0, len(relayPeer.Addrs))
	for _, addrInfo := range relayPeer.Addrs {
		relayAddrs = append(relayAddrs, addrInfo.Addr)
	}
	relayIPv4, relayIPv6 := utils.SeperateAddressesByProtocol(relayAddrs)

	var succes6, succes4 bool

	// Essayer IPv6 d'abord si disponible
	if len(targetIPv6) > 0 && len(relayIPv6) > 0 {
		fmt.Println("🔄 Tentative via IPv6...")
		for _, targetAddr := range targetIPv6 {
			transport.SendNatTraversalRequest(m.server.Conn, relayIPv6[0], targetAddr, m.server.PrivKey)
		}

		if m.pingSpam(targetIPv6, 3, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv6")
			succes6 = true
		}
		// fmt.Println("⚠️ IPv6 a échoué, tentative via IPv4...")
	}
	// Essayer IPv4 si IPv6 a échoué ou n'était pas disponible
	if len(targetIPv4) > 0 && len(relayIPv4) > 0 {
		fmt.Println("🔄 Tentative via IPv4...")
		for _, targetAddr := range targetIPv4 {
			transport.SendNatTraversalRequest(m.server.Conn, relayIPv4[0], targetAddr, m.server.PrivKey)
		}

		if m.pingSpam(targetIPv4, 3, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv4")
			succes4 = true
		}
		// fmt.Println("❌ Échec du NAT traversal via IPv4.")
	}
	if succes4 || succes6 {
		return true
	}
	fmt.Println("❌ Échec du NAT traversal via toutes les adresses.")
	return false
}

// pingSpam envoie plusieurs pings pour percer le NAT avec backoff exponentiel
// Retourne true dès réception d'un ping du pair ou d'un OK en réponse
func (m *InteractiveMenu) pingSpam(addresses []*net.UDPAddr, count int, responseChan chan *net.UDPAddr) bool {
	// Créer une map des adresses cibles pour vérification rapide
	targetAddrs := make(map[string]bool)
	for _, addr := range addresses {
		targetAddrs[addr.String()] = true
	}

	// Calculer le timeout total basé sur le backoff exponentiel
	totalTimeout := utils.CalExpo2Time(count)

	// Démarrer la surveillance
	pierced := make(chan bool, 1)
	go func() {
		timeout := time.After(totalTimeout)
		for {
			select {
			case receivedAddr := <-responseChan:
				if targetAddrs[receivedAddr.String()] {
					pierced <- true
					return
				}
			case <-timeout:
				pierced <- false
				return
			}
		}
	}()

	// Envoyer les pings avec backoff exponentiel
	for i := range count {
		// Envoyer ping à toutes les adresses
		for _, addr := range addresses {
			transport.SendPing(m.server.Conn, addr)
		}

		// Vérifier si on a reçu une réponse
		select {
		case result := <-pierced:
			return result
		default:
		}

		// Attendre avec backoff exponentiel (sauf après le dernier envoi)
		if i < count-1 {
			waitTime := time.Second
			if i > 0 {
				waitTime = time.Duration(1<<uint(i)) * time.Second
			}

			select {
			case result := <-pierced:
				return result
			case <-time.After(waitTime):
			}
		}
	}

	// Attendre le résultat final
	select {
	case result := <-pierced:
		return result
	case <-time.After(500 * time.Millisecond):
		return false
	}
}

// Helper pour choisir un peer connecté
func (m *InteractiveMenu) pickConnectedPeer() (*peer.PeerInfo, string) {
	connectedPeers := m.server.PeerManager.List()
	if len(connectedPeers) == 0 {
		fmt.Println("Aucun peer connecté (utilisez l'option 2).")
		return nil, ""
	}

	fmt.Println("Peers connectés:")
	for i, pName := range connectedPeers {
		fmt.Printf("  %d. %s\n", i+1, pName)
	}

	peerChoice := m.ask("Choix (nom ou numéro) : ")

	// Support choix par index
	if peerIndex, err := strconv.Atoi(peerChoice); err == nil && peerIndex > 0 && peerIndex <= len(connectedPeers) {
		pInfo, _ := m.server.PeerManager.Get(connectedPeers[peerIndex-1])
		return pInfo, connectedPeers[peerIndex-1]
	}
	// Support choix par nom
	if pInfo, ok := m.server.PeerManager.Get(peerChoice); ok {
		return pInfo, peerChoice
	} else {
		fmt.Printf("Peer '%s' non connecté\n", peerChoice)
		return nil, ""
	}
}

// Helper pour obtenir le hash racine depuis un peer
func (m *InteractiveMenu) getRootHashFromPeer(pInfo *peer.PeerInfo, pName string) [32]byte {
	fmt.Printf("🔍 Demande du hash racine à %s...\n", pName)
	m.rootHashChan = make(chan [32]byte, 1)
	m.server.SetRootHashChan(m.rootHashChan)
	transport.SendRootRequest(m.server.Conn, pInfo.GetAddr())

	fmt.Println("⌛ En attente de la réponse...")

	var targetHash [32]byte
	select {
	case tmpHash := <-m.rootHashChan:
		fmt.Println("✅ Réception du hash racine réussie")
		targetHash = tmpHash
	case <-time.After(3 * time.Second):
		fmt.Println("⏳ Timeout: pas de réponse reçue (3s)")
	}

	m.server.SetRootHashChan(nil)
	return targetHash
}

// filterAddressesByProtocol filtre les adresses en fonction des protocols locales
func (m *InteractiveMenu) filterAddressesByProtocol(addresses []*net.UDPAddr) []*net.UDPAddr {
	if !m.hasIPv4 && !m.hasIPv6 {
		fmt.Println("⚠️ Aucun protocole IP disponible !")
		return nil
	}

	var filtered []*net.UDPAddr
	for _, addr := range addresses {
		isIPv4 := addr.IP.To4() != nil

		if isIPv4 && m.hasIPv4 {
			filtered = append(filtered, addr)
		} else if !isIPv4 && m.hasIPv6 {
			filtered = append(filtered, addr)
		}
	}

	if len(filtered) == 0 {
		fmt.Println("⚠️ Aucune adresse compatible avec nos protocols IP")
	}

	return filtered
}
