package menu

import (
	"bufio"
	"context"
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

type InteractiveMenu struct {
	server       *transport.Server
	serverAddr   *net.UDPAddr
	scanner      *bufio.Scanner
	rootHashChan chan [32]byte
	hasIPv4      bool
	hasIPv6      bool
}

func NewMenu(server *transport.Server, serverAddr *net.UDPAddr) *InteractiveMenu {
	// Détecter les protocols IP locales une seule fois
	hasIPv4, hasIPv6 := utils.DetectLocalIPProtocol()

	return &InteractiveMenu{
		server:     server,
		serverAddr: serverAddr,
		scanner:    bufio.NewScanner(os.Stdin),
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

// 2. Se connecter (Direct + NAT Traversal)
func (m *InteractiveMenu) connectToPeer() {
	pName := m.ask("Nom du peer cible : ")
	if pName == "" {
		fmt.Println("Nom de peer vide")
		return
	}
	// Récup IP
	rawAddr, err := transport.GetAddr(pName)
	if err != nil {
		fmt.Printf("Impossible de récupérer les adresses de %s: %v\n", pName, err)
		return
	}

	// Parser et résoudre les adresses
	targets := utils.AddrParserSolver(rawAddr)
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
	isConnected := m.sendDirectConnection(targets, pName, 5)

	// Phase 2: NAT traversal si la connexion directe échoue
	if !isConnected {
		// Demander quel relais utiliser
		fmt.Println("\n--- Choix du relais pour NAT traversal ---")
		fmt.Println("Appuyez sur Entrée (ou tapez 'default') pour utiliser le serveur central")
		fmt.Println("Ou entrez le nom d'un peer connecté pour l'utiliser comme relais")
		relayChoice := m.ask("Relais : ")
		relayChoice = strings.TrimSpace(relayChoice)

		// Configurer le canal de réception AVANT d'envoyer les requêtes NAT
		responseChan := make(chan *net.UDPAddr, 5)
		m.server.PingResponseMu.Lock()
		m.server.PingResponseChan = responseChan
		m.server.PingResponseMu.Unlock()

		if relayChoice == "" || relayChoice == "default" {
			// Utiliser le serveur central
			relayChoice = "jch.irif.fr"
		}
		fmt.Printf("--- Tentative NAT traversal via %s... ---\n", relayChoice)
		natPierced, usedAddrs := m.sendNatTraversalViaPeer(targets, relayChoice, responseChan, pName)

		// Cleanup du canal
		m.server.PingResponseMu.Lock()
		m.server.PingResponseChan = nil
		m.server.PingResponseMu.Unlock()

		// Si le NAT est percé, tenter la connexion avec Hello sur les adresses qui ont fonctionné
		if natPierced {
			isConnected = m.sendDirectConnection(usedAddrs, pName, 5)
		}
	}

	if isConnected {
		fmt.Printf("✅ SUCCÈS : Connecté à %s !\n", pName)
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
	m.printTree(m.server.Downloads, targetHash, "", "", true)
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
		// Parser le hash entré par l'utilisateur
		parsedHash, err := utils.ParseHash(hashInput)
		if err != nil {
			return
		}
		targetHash = parsedHash
	}
	// Gestion Ctrl+C
	dlCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
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
			for i, addr := range info.Addrs {
				fmt.Printf("	Adresse %d: %s\n", i+1, addr)
			}
			fmt.Printf("    Dernière activité: %s\n", info.LastSeen.Format("15:04:05"))
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
	m.printTree(m.server.MerkleStore, m.server.RootHash, "  ", "", true)

	m.waitKey()
}

// Une interface pour gérer d'où viennent les données (DL arbo ou DL disque)
type DatumProvider interface {
	Get(hash [32]byte) ([]byte, bool)
}

func (m *InteractiveMenu) printTree(provider DatumProvider, hash [32]byte, prefix, fileName string, isLast bool) {
	datum, found := provider.Get(hash)

	marker := "├── "
	if isLast {
		marker = "└── "
	}

	if !found {
		fmt.Printf("%s%s [???] nom: %s (manquant) %x\n", prefix, marker, fileName, hash)
		return
	}
	nodeType, nodeData := merkle.ParseDatum(datum)

	newPrefix := prefix + "│   "
	if isLast {
		newPrefix = prefix + "    "
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(nodeData)
		fmt.Printf("%s%s%s 📁 [DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			m.printTree(provider, e.Hash, newPrefix, merkle.GetEntryName(e), i == len(entries)-1)
		}
	case merkle.TypeBigDirectory:
		entries := merkle.ParseBigHashes(nodeData)
		fmt.Printf("%s%s%s 📁 [BIG-DIR] (%d items) %x\n", prefix, marker, fileName, len(entries), hash)

		for i, e := range entries {
			m.printTree(provider, e, newPrefix, "", i == len(entries)-1)
		}
	case merkle.TypeChunk:
		fmt.Printf("%s%s%s 📄 [FILE] (%s) %x\n", prefix, marker, fileName, utils.FormatBytesInt64(int64(len(nodeData))), hash)

	case merkle.TypeBig:
		fmt.Printf("%s%s%s 📄 [BIG-FILE] (%s) %x\n", prefix, marker, fileName, utils.FormatBytesInt64(int64(len(nodeData))), hash)
	}
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
	// Capturer le timestamp actuel avant d'envoyer les Hello
	startTime := time.Now()

	for range maxAttempts {
		for _, addr := range addresses {
			transport.SendHello(m.server.Conn, addr, m.server.MyName, m.server.PrivKey)
		}
		time.Sleep(300 * time.Millisecond)

		// Vérifier si le peer existe et a été vu récemment
		if peerInfo, exists := m.server.PeerManager.Get(pName); exists {
			// Le peer doit avoir été vu après qu'on ait commencé à envoyer les Hello
			if peerInfo.LastSeen.After(startTime) {
				return true
			}
		}
	}
	return false
}

// sendNatTraversalViaPeer utilise un peer comme relais pour le NAT traversal
func (m *InteractiveMenu) sendNatTraversalViaPeer(targetAddresses []*net.UDPAddr, relayPeerName string, responseChan chan *net.UDPAddr, pName string) (bool, []*net.UDPAddr) {
	// Vérifier que le peer relais est connecté
	relayPeer, exists := m.server.PeerManager.Get(relayPeerName)
	if !exists {
		fmt.Printf("❌ Peer relais %s non connecté. Vous devez d'abord être connecté avec ce peer.\n", relayPeerName)
		return false, nil
	}

	fmt.Printf("🚀 Utilisation de %s comme relais (%d adresse(s))\n", relayPeerName, len(relayPeer.Addrs))

	// Filtrer les adresses en fonction de nos protocols
	filteredTargets := m.filterAddressesByProtocol(targetAddresses)
	if len(filteredTargets) == 0 {
		fmt.Println("❌ Aucune adresse cible compatible avec nos protocols IP.")
		return false, nil
	}

	filteredRelayAddrs := m.filterAddressesByProtocol(relayPeer.Addrs)
	if len(filteredRelayAddrs) == 0 {
		fmt.Printf("❌ Le peer relais %s n'a pas d'adresses compatibles avec nos protocols IP.\n", relayPeerName)
		return false, nil
	}

	res, targetIPv4, targetIPv6, relayIPv4, relayIPv6 := utils.FiltrerAddressesByProtocol(filteredTargets, filteredRelayAddrs)
	if !res {
		fmt.Printf("❌ Aucun protocole compatible entre le relais %s et la cible.\n", relayPeerName)
		return false, nil
	}

	// Essayer IPv6 d'abord si disponible
	if len(targetIPv6) > 0 && len(relayIPv6) > 0 {
		fmt.Println("🔄 Tentative via IPv6...")
		for _, targetAddr := range targetIPv6 {
			for _, relayAddr := range relayIPv6 {
				transport.SendNatTraversalRequest(m.server.Conn, relayAddr, targetAddr, m.server.PrivKey)
			}
		}

		// Tester avec pingSpam
		if m.pingSpam(targetIPv6, pName, 3, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv6")
			return true, targetIPv6
		}
		fmt.Println("⚠️ IPv6 a échoué, tentative via IPv4...")
	}

	// Essayer IPv4 si IPv6 a échoué ou n'était pas disponible
	if len(targetIPv4) > 0 && len(relayIPv4) > 0 {
		fmt.Println("🔄 Tentative via IPv4...")
		for _, targetAddr := range targetIPv4 {
			for _, relayAddr := range relayIPv4 {
				transport.SendNatTraversalRequest(m.server.Conn, relayAddr, targetAddr, m.server.PrivKey)
			}
		}

		// Tester avec pingSpam
		if m.pingSpam(targetIPv4, pName, 3, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv4")
			return true, targetIPv4
		}
	}

	return false, nil
}

// pingSpam envoie plusieurs pings pour percer le NAT avec backoff exponentiel
// Retourne true dès réception d'un ping du pair ou d'un OK en réponse
// Utilise un backoff exponentiel : 0s, 1s, 2s, 4s, 8s, etc.
func (m *InteractiveMenu) pingSpam(addresses []*net.UDPAddr, _ string, count int, responseChan chan *net.UDPAddr) bool {
	// Créer une map des adresses cibles pour vérification rapide
	targetAddrs := make(map[string]bool)
	for _, addr := range addresses {
		targetAddrs[addr.String()] = true
	}

	// Canal pour signaler l'arrêt
	stopSending := make(chan bool)

	// Calculer le timeout total basé sur le backoff exponentiel
	totalTimeout := time.Duration(0)
	for i := range count {
		if i == 0 {
			// Premier envoi immédiat
			continue
		}
		totalTimeout += time.Duration(1<<uint(i-1)) * time.Second
	}

	// Démarrer la surveillance
	pierced := make(chan bool, 1)
	go func() {
		for {
			select {
			case receivedAddr := <-responseChan:
				// Vérifier si c'est une des adresses cibles
				if targetAddrs[receivedAddr.String()] {
					close(stopSending) // Arrêter l'envoi immédiatement
					select {
					case pierced <- true:
					default:
					}
					return
				}
			case <-time.After(totalTimeout):
				select {
				case pierced <- false:
				default:
				}
				return
			}
		}
	}()

	// Vérifier si on a déjà reçu quelque chose
	select {
	case result := <-pierced:
		return result
	default:
		// Continuer avec l'envoi de pings
	}

	// Envoyer les pings avec backoff exponentiel
	for i := range count {
		select {
		case <-stopSending:
			// Réception détectée, on arrête d'envoyer
			result := <-pierced
			return result
		default:
			// Envoyer ping à toutes les adresses
			for _, addr := range addresses {
				transport.SendPing(m.server.Conn, addr)
			}

			// Attendre avec backoff exponentiel
			if i < count-1 { // Pas d'attente après le dernier envoi
				var waitTime time.Duration
				if i == 0 {
					waitTime = 1 * time.Second
				} else {
					waitTime = time.Duration(1<<uint(i)) * time.Second
				}

				// Attendre avec possibilité d'interruption
				select {
				case <-stopSending:
					result := <-pierced
					return result
				case <-time.After(waitTime):
					// Continuer à la prochaine itération
				}
			}
		}
	}

	// Attendre le résultat final
	select {
	case result := <-pierced:
		if result {
			fmt.Println("✓ NAT percé!")
		}
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
