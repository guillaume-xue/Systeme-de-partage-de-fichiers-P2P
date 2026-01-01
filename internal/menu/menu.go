package menu

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"main/internal/merkle"
	"main/internal/peer"
	"main/internal/protocol"
	"main/internal/transport"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// InteractiveMenu représente l'interface utilisateur interactive
type InteractiveMenu struct {
	server       *transport.Server
	serverAddr   *net.UDPAddr
	inputReader  *bufio.Reader
	rootHashChan chan [32]byte
}

// NewMenu crée une nouvelle instance du menu interactif
func NewMenu(server *transport.Server, serverAddr *net.UDPAddr) *InteractiveMenu {
	return &InteractiveMenu{
		server:      server,
		serverAddr:  serverAddr,
		inputReader: bufio.NewReader(os.Stdin),
	}
}

// Run démarre la boucle principale du menu interactif
func (m *InteractiveMenu) Run() {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("  🌐 Client P2P - Système de fichiers distribué")
	fmt.Println(strings.Repeat("=", 50))

	for {
		m.displayMainMenu()
		peerChoice := m.readUserInput("Choix: ")
		fmt.Println()
		switch strings.TrimSpace(peerChoice) {
		case "1":
			m.handleListAvailablePeers()
		case "2":
			m.handleConnectToPeer()
		case "3":
			m.handleExplorePeerFiles()
		case "4":
			m.handleDownloadFiles()
		case "5":
			m.handleShowConnectedPeers()
		case "6":
			m.handleShowSharedFiles()
		case "7":
			m.handleShowDownloadsFolder()
		case "0", "q", "quit", "exit":
			fmt.Println("\n👋 Fermeture en cours...")
			m.server.Stop()
			fmt.Println("✅ Au revoir!")
			return
		default:
			fmt.Println("⚠️ Choix invalide")
		}
	}
}

// displayMainMenu affiche le menu principal
func (m *InteractiveMenu) displayMainMenu() {
	fmt.Println("\n┌─────────────────────────────────┐")
	fmt.Println("│          MENU PRINCIPAL         │")
	fmt.Println("├─────────────────────────────────┤")
	fmt.Println("│ 1. Lister les peers disponibles │")
	fmt.Println("│ 2. Se connecter à un peer       │")
	fmt.Println("│ 3. Explorer les fichiers        │")
	fmt.Println("│ 4. Télécharger sur disque       │")
	fmt.Println("│ 5. Peers connectés              │")
	fmt.Println("│ 6. Mes fichiers partagés        │")
	fmt.Println("│ 7. Ouvrir dossier downloads     │")
	fmt.Println("├─────────────────────────────────┤")
	fmt.Println("│ 0. Quitter                      │")
	fmt.Println("└─────────────────────────────────┘")
}

// readUserInput lit une ligne de texte de l'utilisateur
func (m *InteractiveMenu) readUserInput(prompt string) string {
	fmt.Print(prompt)
	line, _ := m.inputReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// waitForEnterKey attend que l'utilisateur appuie sur Entrée
func (m *InteractiveMenu) waitForEnterKey() {
	fmt.Print("\n⏎ Appuyez sur Entrée pour continuer...")
	m.inputReader.ReadString('\n')
}

// parseHashFromHexString convertit une chaîne hexadécimale en hash [32]byte
// Accepte les formats: "abc123...", "0xabc123...", avec ou sans espaces
func parseHashFromHexString(hexInput string) ([32]byte, error) {
	var hash [32]byte

	// Nettoyer l'entrée
	cleanedInput := strings.TrimSpace(hexInput)
	cleanedInput = strings.ReplaceAll(cleanedInput, " ", "")
	cleanedInput = strings.ReplaceAll(cleanedInput, "\t", "")

	// Supprimer le préfixe "0x" si présent
	cleanedInput = strings.TrimPrefix(cleanedInput, "0x")
	cleanedInput = strings.TrimPrefix(cleanedInput, "0X")

	// Convertir en minuscules
	cleanedInput = strings.ToLower(cleanedInput)

	// Vérifier la longueur (un hash SHA-256 = 64 caractères hex)
	if len(cleanedInput) < 64 {
		return hash, fmt.Errorf("⚠️ Hash trop court (%d caractères, attendu 64)", len(cleanedInput))
	}

	// Prendre les 64 premiers caractères
	cleanedInput = cleanedInput[:64]

	// Décoder l'hexadécimal
	decodedBytes, err := hex.DecodeString(cleanedInput)
	if err != nil {
		return hash, fmt.Errorf("⚠️ Hash invalide (caractères non-hexadécimaux): %v", err)
	}

	copy(hash[:], decodedBytes)
	return hash, nil
}

// ===========================================================================
// Handlers des options du menu
// ===========================================================================

// handleListAvailablePeers affiche tous les peers enregistrés sur le serveur
func (m *InteractiveMenu) handleListAvailablePeers() {
	fmt.Println("\n📡 Récupération de la liste des peers...")

	peerList, err := transport.GetListPeers()
	if err != nil {
		fmt.Printf("⚠️ Impossible de récupérer la liste des peers: %v\n", err)
		return
	}

	if len(peerList) == 0 {
		fmt.Println("📋 Aucun peer enregistré")
		return
	}

	fmt.Printf("\n📋 %d peers disponibles:\n", len(peerList))
	fmt.Println(strings.Repeat("-", 40))
	for index, peerName := range peerList {
		fmt.Printf("  %2d. %s\n", index+1, peerName)
	}
	fmt.Println(strings.Repeat("-", 40))
	m.waitForEnterKey()
}

// handleConnectToPeer établit une connexion avec un peer via NAT traversal
func (m *InteractiveMenu) handleConnectToPeer() {
	peerName := m.readUserInput("\nNom du peer: ")
	if peerName == "" {
		fmt.Println("⚠️ Nom de peer vide")
		return
	}

	// Récupérer les adresses du peer depuis le serveur HTTP
	addressesRaw, err := transport.GetAddr(peerName)
	if err != nil {
		fmt.Printf("⚠️ Impossible de récupérer les adresses de %s: %v\n", peerName, err)
		return
	}

	// Parser et résoudre les adresses
	var peerAddresses []*net.UDPAddr
	for addrLine := range strings.SplitSeq(strings.TrimSpace(addressesRaw), "\n") {
		addrLine = strings.TrimSpace(addrLine)
		if addrLine == "" {
			continue
		}
		resolvedAddr, err := net.ResolveUDPAddr("udp", addrLine)
		if err == nil {
			peerAddresses = append(peerAddresses, resolvedAddr)
			ipVersion := "IPv4"
			if resolvedAddr.IP.To4() == nil {
				ipVersion = "IPv6"
			}
			fmt.Printf("  📍 %s [%s]\n", addrLine, ipVersion)
		}
	}

	if len(peerAddresses) == 0 {
		fmt.Printf("⚠️ Aucune adresse valide pour %s\n", peerName)
		m.waitForEnterKey()
		return
	}

	fmt.Println("\n🔗 Connexion en cours...")

	// Phase 1: Tentatives de connexion directe
	isConnected := m.attemptDirectConnection(peerAddresses, peerName, 5)

	// Phase 2: NAT traversal si la connexion directe échoue
	if !isConnected {
		fmt.Println("↪️ Tentative NAT traversal via serveur...")
		m.sendNatTraversalRequests(peerAddresses)
		time.Sleep(500 * time.Millisecond) // Attendre que le NAT s'ouvre
		isConnected = m.attemptDirectConnection(peerAddresses, peerName, 5)
	}

	if isConnected {
		fmt.Printf("✅ Connecté à %s\n", peerName)
	} else {
		fmt.Printf("⚠️ Impossible de se connecter à %s\n", peerName)
	}

	m.waitForEnterKey()
}

// attemptDirectConnection tente une connexion directe avec retries
func (m *InteractiveMenu) attemptDirectConnection(addresses []*net.UDPAddr, peerName string, maxAttempts int) bool {
	for range maxAttempts {
		for _, addr := range addresses {
			transport.SendHello(m.server.Conn, addr, m.server.MyName, m.server.PrivKey)
		}
		time.Sleep(300 * time.Millisecond)
		if _, exists := m.server.PeerManager.Get(peerName); exists {
			return true
		}
	}
	return false
}

// sendNatTraversalRequests envoie les requêtes NAT traversal au serveur
func (m *InteractiveMenu) sendNatTraversalRequests(targetAddresses []*net.UDPAddr) {
	for _, targetAddr := range targetAddresses {
		var relayServerAddr *net.UDPAddr
		if targetAddr.IP.To4() != nil {
			relayServerAddr, _ = net.ResolveUDPAddr("udp", protocol.ServerUDPv4)
		} else {
			relayServerAddr, _ = net.ResolveUDPAddr("udp", protocol.ServerUDPv6)
		}
		if relayServerAddr != nil {
			transport.SendNatTraversalRequest(m.server.Conn, relayServerAddr, targetAddr, m.server.PrivKey)
		} else {
			fmt.Printf("⚠️ Impossible de résoudre l'adresse du serveur de relais pour %s\n", targetAddr.String())
		}
	}
}

// getSelectedPeerInfo demande à l'utilisateur de sélectionner un peer connecté
func (m *InteractiveMenu) getSelectedPeerInfo() (*peer.PeerInfo, string) {
	connectedPeers := m.server.PeerManager.List()
	if len(connectedPeers) == 0 {
		fmt.Println("⚠️ Aucun peer connecté. Utilisez l'option 2 d'abord.")
		return nil, ""
	}

	fmt.Println("📡 Peers connectés:")
	for index, name := range connectedPeers {
		fmt.Printf("  %d. %s\n", index+1, name)
	}

	peerChoice := m.readUserInput("Numéro du peer (ou nom): ")
	fmt.Println()

	// Déterminer le nom du peer sélectionné
	var selectedPeerName string
	if peerIndex, err := strconv.Atoi(peerChoice); err == nil && peerIndex > 0 && peerIndex <= len(connectedPeers) {
		selectedPeerName = connectedPeers[peerIndex-1]
	} else {
		selectedPeerName = peerChoice
	}

	peerInfo, exists := m.server.PeerManager.Get(selectedPeerName)
	if !exists {
		fmt.Printf("⚠️ Peer '%s' non connecté\n", selectedPeerName)
		return nil, ""
	}
	return peerInfo, selectedPeerName
}

// getRootHashFromPeer demande le hash racine au peer sélectionné
func (m *InteractiveMenu) getRootHashFromPeer(peerInfo *peer.PeerInfo, selectedPeerName string) [32]byte {
	// Demander le hash racine au peer
	fmt.Printf("🔍 Demande du hash racine à %s...\n", selectedPeerName)
	m.rootHashChan = make(chan [32]byte, 1)
	m.server.SetRootHashChan(m.rootHashChan)
	transport.SendRootRequest(m.server.Conn, peerInfo.Addr)

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

// handleExplorePeerFiles explore l'arborescence des fichiers d'un peer
func (m *InteractiveMenu) handleExplorePeerFiles() {
	peerInfo, selectedPeerName := m.getSelectedPeerInfo()
	if peerInfo == nil {
		return
	}

	targetHash := m.getRootHashFromPeer(peerInfo, selectedPeerName)
	if targetHash == ([32]byte{}) {
		return
	}

	// Télécharger l'arborescence
	fmt.Println("\n📥 Téléchargement de l'arborescence en cours...")
	treeDownloader := transport.NewDownloader(m.server, peerInfo.Addr)
	m.server.OnDatumReceived = func(hash [32]byte, datum []byte) {
		treeDownloader.NotifyReceived(hash, datum)
	}
	treeDownloader.DownloadTree(targetHash)
	m.server.OnDatumReceived = nil

	// Afficher l'arborescence
	fmt.Println("\n📂 Arborescence:")
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("🌳 Racine: %x\n\n", targetHash)
	m.displayFileTree(targetHash, "", "", true)
	fmt.Println(strings.Repeat("─", 70))

	m.waitForEnterKey()
}

// handleDownloadFiles télécharge les fichiers d'un peer sur le disque
func (m *InteractiveMenu) handleDownloadFiles() {
	peerInfo, selectedPeerName := m.getSelectedPeerInfo()
	if peerInfo == nil {
		return
	}

	// Demander le hash à télécharger
	hashInput := m.readUserInput("Hash du datum (hex, ou 'root' pour la racine): ")

	var targetHash [32]byte
	if hashInput == "root" {
		targetHash = m.getRootHashFromPeer(peerInfo, selectedPeerName)
		if targetHash == ([32]byte{}) {
			return
		}
	} else {
		// Parser le hash entré par l'utilisateur
		parsedHash, err := parseHashFromHexString(hashInput)
		if err != nil {
			return
		}
		targetHash = parsedHash
	}

	// Télécharger sur le disque
	m.downloadFilesToDisk(selectedPeerName, peerInfo.Addr, targetHash)
	m.waitForEnterKey()
}

// downloadFilesToDisk télécharge les fichiers directement sur le disque
func (m *InteractiveMenu) downloadFilesToDisk(peerName string, peerAddr *net.UDPAddr, targetHash [32]byte) {
	sanitizedName := sanitizeFolderName(peerName)
	destinationDir := filepath.Join("downloads", sanitizedName)

	fmt.Printf("📂 Destination: %s\n", destinationDir)

	diskDownloader := transport.NewDiskDownloader(m.server, peerAddr, destinationDir)
	m.server.OnDatumReceived = func(hash [32]byte, datum []byte) {
		diskDownloader.NotifyReceived(hash, datum)
	}

	if err := diskDownloader.DownloadToDisk(targetHash); err != nil {
		fmt.Printf("❌ Erreur lors du téléchargement: %v\n", err)
	}

	m.server.OnDatumReceived = nil
}

// sanitizeFolderName nettoie un nom pour l'utiliser comme nom de dossier
func sanitizeFolderName(name string) string {
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return replacer.Replace(name)
}

// handleShowConnectedPeers affiche la liste des peers actuellement connectés
func (m *InteractiveMenu) handleShowConnectedPeers() {
	connectedPeers := m.server.PeerManager.List()

	fmt.Println("\n🔗 Peers connectés:")
	fmt.Println(strings.Repeat("-", 50))

	if len(connectedPeers) == 0 {
		fmt.Println("  Aucun peer connecté")
	} else {
		for _, name := range connectedPeers {
			info, _ := m.server.PeerManager.Get(name)
			fmt.Printf("  • %s\n", name)
			fmt.Printf("    Adresse: %s\n", info.Addr)
			fmt.Printf("    Dernière activité: %s\n", info.LastSeen.Format("15:04:05"))
		}
	}
	fmt.Println(strings.Repeat("-", 50))
	m.waitForEnterKey()
}

// handleShowSharedFiles affiche les fichiers partagés localement
func (m *InteractiveMenu) handleShowSharedFiles() {
	fmt.Println("\n📁 Mes fichiers partagés:")
	fmt.Println(strings.Repeat("─", 70))

	emptyHash := [32]byte{}
	if m.server.RootHash == emptyHash {
		fmt.Println("  Aucun fichier partagé")
		fmt.Println(strings.Repeat("─", 70))
		m.waitForEnterKey()
		return
	}

	fmt.Printf("  Hash racine: %x\n", m.server.RootHash)
	fmt.Printf("  Datums dans le store: %d\n", m.server.MerkleStore.Len())

	fmt.Println("\n  Arborescence:")
	m.displayLocalFileTree(m.server.RootHash, "  ", "", true)

	fmt.Println(strings.Repeat("─", 70))
	m.waitForEnterKey()
}

// handleShowDownloadsFolder affiche le contenu du dossier de téléchargements
func (m *InteractiveMenu) handleShowDownloadsFolder() {
	fmt.Println("\n📂 Dossier downloads:")
	fmt.Println(strings.Repeat("─", 70))

	if _, err := os.Stat("downloads"); os.IsNotExist(err) {
		fmt.Println("  Aucun téléchargement effectué")
		fmt.Println("  Utilisez l'option 4 pour télécharger des fichiers")
		fmt.Println(strings.Repeat("─", 70))
		m.waitForEnterKey()
		return
	}

	dirEntries, err := os.ReadDir("downloads")
	if err != nil {
		fmt.Printf("⚠️ Impossible de lire le dossier downloads: %v\n", err)
		m.waitForEnterKey()
		return
	}

	if len(dirEntries) == 0 {
		fmt.Println("  Dossier downloads vide")
		fmt.Println(strings.Repeat("─", 70))
		m.waitForEnterKey()
		return
	}

	fmt.Printf("  %d peer(s) téléchargé(s):\n\n", len(dirEntries))
	for _, entry := range dirEntries {
		if !entry.IsDir() {
			continue
		}
		peerDirPath := filepath.Join("downloads", entry.Name())
		fileCount, totalSize := countFilesInDirectory(peerDirPath)
		fmt.Printf("  📁 %s\n", entry.Name())
		fmt.Printf("     └── %d fichier(s), %s\n", fileCount, formatBytesInt64(totalSize))
	}

	fmt.Println(strings.Repeat("─", 70))
	fmt.Println("\n📍 Emplacement: ./downloads/")
	m.waitForEnterKey()
}

// ===========================================================================
// Fonctions utilitaires d'affichage
// ===========================================================================

// displayFileTree affiche l'arborescence des fichiers téléchargés
func (m *InteractiveMenu) displayFileTree(hash [32]byte, prefix string, fileName string, isLastChild bool) {
	// Chercher le datum dans les téléchargements ou le store local
	datum, found := m.server.Downloads.Get(hash)
	if !found {
		datum, found = m.server.MerkleStore.Get(hash)
	}

	// Caractères pour l'arborescence
	connector := "├── "
	if isLastChild {
		connector = "└── "
	}

	if !found {
		if fileName != "" {
			fmt.Printf("%s%s❓ %s (non téléchargé)\n", prefix, connector, fileName)
		} else {
			fmt.Printf("%s%s❓ (non téléchargé)\n", prefix, connector)
		}
		fmt.Printf("%s    Hash: %x\n", prefix, hash)
		return
	}

	nodeType, nodeData := merkle.ParseDatum(datum)

	// Calculer le préfixe pour les enfants
	childPrefix := prefix
	if fileName != "" {
		if isLastChild {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "│   "
		}
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(nodeData)
		if fileName != "" {
			fmt.Printf("%s%s📁 %s/ [Dir, %d entrées] %x\n", prefix, connector, fileName, len(entries), hash)
		} else {
			fmt.Printf("%s📁 / [Dir, %d entrées] %x\n", prefix, len(entries), hash)
		}
		for i, entry := range entries {
			entryName := merkle.GetEntryName(entry)
			m.displayFileTree(entry.Hash, childPrefix, entryName, i == len(entries)-1)
		}

	case merkle.TypeBigDirectory:
		childHashes := merkle.ParseBigHashes(nodeData)
		if fileName != "" {
			fmt.Printf("%s%s📁 %s/ [BigDir, %d parties] %x\n", prefix, connector, fileName, len(childHashes), hash)
		} else {
			fmt.Printf("%s📁 / [BigDir, %d parties] %x\n", prefix, len(childHashes), hash)
		}
		for i, childHash := range childHashes {
			m.displayFileTree(childHash, childPrefix, "", i == len(childHashes)-1)
		}

	case merkle.TypeChunk:
		sizeStr := formatBytes(len(nodeData))
		textPreview := ""
		if len(nodeData) > 0 && isTextData(nodeData[:minInt(len(nodeData), 30)]) {
			textPreview = fmt.Sprintf(" \"%s\"", string(nodeData[:minInt(len(nodeData), 30)]))
			if len(nodeData) > 30 {
				textPreview = textPreview[:len(textPreview)-1] + "...\""
			}
		}
		if fileName != "" {
			fmt.Printf("%s%s📄 %s [Chunk, %s]%s %x\n", prefix, connector, fileName, sizeStr, textPreview, hash)
		} else {
			fmt.Printf("%s%s📄 [Chunk, %s]%s %x\n", prefix, connector, sizeStr, textPreview, hash)
		}

	case merkle.TypeBig:
		childHashes := merkle.ParseBigHashes(nodeData)
		totalSize := m.calculateBigFileSize(hash)
		sizeStr := "?"
		if totalSize > 0 {
			sizeStr = formatBytes(totalSize)
		}
		if fileName != "" {
			fmt.Printf("%s%s📄 %s [Big, %s, %d parties] %x\n", prefix, connector, fileName, sizeStr, len(childHashes), hash)
		} else {
			fmt.Printf("%s%s📄 [Big, %s, %d parties] %x\n", prefix, connector, sizeStr, len(childHashes), hash)
		}
	}
}

// displayLocalFileTree affiche l'arborescence des fichiers locaux
func (m *InteractiveMenu) displayLocalFileTree(hash [32]byte, prefix string, fileName string, isLastChild bool) {
	datum, found := m.server.MerkleStore.Get(hash)
	if !found {
		return
	}

	connector := "├── "
	if isLastChild {
		connector = "└── "
	}

	nodeType, nodeData := merkle.ParseDatum(datum)

	childPrefix := prefix
	if fileName != "" {
		if isLastChild {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "│   "
		}
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(nodeData)
		if fileName != "" {
			fmt.Printf("%s%s📁 %s/ [Dir, %d entrées, %x...]\n", prefix, connector, fileName, len(entries), hash[:8])
		} else {
			fmt.Printf("%s📁 / [Dir, %d entrées, %x...]\n", prefix, len(entries), hash[:8])
		}
		for i, entry := range entries {
			entryName := merkle.GetEntryName(entry)
			m.displayLocalFileTree(entry.Hash, childPrefix, entryName, i == len(entries)-1)
		}

	case merkle.TypeBigDirectory:
		childHashes := merkle.ParseBigHashes(nodeData)
		if fileName != "" {
			fmt.Printf("%s%s📁 %s/ [BigDir, %d parties, %x...]\n", prefix, connector, fileName, len(childHashes), hash[:8])
		} else {
			fmt.Printf("%s📁 / [BigDir, %d parties, %x...]\n", prefix, len(childHashes), hash[:8])
		}
		for i, childHash := range childHashes {
			m.displayLocalFileTree(childHash, childPrefix, "", i == len(childHashes)-1)
		}

	case merkle.TypeChunk:
		sizeStr := formatBytes(len(nodeData))
		if fileName != "" {
			fmt.Printf("%s%s📄 %s [Chunk, %s, %x...]\n", prefix, connector, fileName, sizeStr, hash[:8])
		} else {
			fmt.Printf("%s%s📄 [Chunk, %s, %x...]\n", prefix, connector, sizeStr, hash[:8])
		}

	case merkle.TypeBig:
		childHashes := merkle.ParseBigHashes(nodeData)
		totalSize := m.calculateLocalBigFileSize(hash)
		sizeStr := formatBytes(totalSize)
		if fileName != "" {
			fmt.Printf("%s%s📄 %s [Big, %s, %d parties, %x...]\n", prefix, connector, fileName, sizeStr, len(childHashes), hash[:8])
		} else {
			fmt.Printf("%s%s📄 [Big, %s, %d parties, %x...]\n", prefix, connector, sizeStr, len(childHashes), hash[:8])
		}
	}
}

// calculateBigFileSize calcule la taille totale d'un fichier Big (téléchargé)
func (m *InteractiveMenu) calculateBigFileSize(hash [32]byte) int {
	datum, found := m.server.Downloads.Get(hash)
	if !found {
		return 0
	}
	nodeType, nodeData := merkle.ParseDatum(datum)

	switch nodeType {
	case merkle.TypeChunk:
		return len(nodeData)
	case merkle.TypeBig:
		totalSize := 0
		for _, childHash := range merkle.ParseBigHashes(nodeData) {
			childSize := m.calculateBigFileSize(childHash)
			if childSize == 0 {
				return 0 // Un chunk manque
			}
			totalSize += childSize
		}
		return totalSize
	}
	return 0
}

// calculateLocalBigFileSize calcule la taille d'un fichier Big local
func (m *InteractiveMenu) calculateLocalBigFileSize(hash [32]byte) int {
	datum, found := m.server.MerkleStore.Get(hash)
	if !found {
		return 0
	}
	nodeType, nodeData := merkle.ParseDatum(datum)

	switch nodeType {
	case merkle.TypeChunk:
		return len(nodeData)
	case merkle.TypeBig:
		totalSize := 0
		for _, childHash := range merkle.ParseBigHashes(nodeData) {
			totalSize += m.calculateLocalBigFileSize(childHash)
		}
		return totalSize
	}
	return 0
}

// ===========================================================================
// Fonctions utilitaires générales
// ===========================================================================

// countFilesInDirectory compte les fichiers et calcule la taille totale d'un dossier
func countFilesInDirectory(dirPath string) (int, int64) {
	var fileCount int
	var totalSize int64
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			fileCount++
			totalSize += info.Size()
		}
		return nil
	})
	return fileCount, totalSize
}

// formatBytes formate une taille en bytes de façon lisible
func formatBytes(byteCount int) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

// formatBytesInt64 formate une taille int64 en bytes de façon lisible
func formatBytesInt64(byteCount int64) string {
	if byteCount < 1024 {
		return fmt.Sprintf("%d B", byteCount)
	} else if byteCount < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(byteCount)/(1024*1024))
}

// isTextData vérifie si les données sont du texte affichable
func isTextData(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
		if b > 126 {
			return false
		}
	}
	return true
}

// minInt retourne le minimum de deux entiers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
