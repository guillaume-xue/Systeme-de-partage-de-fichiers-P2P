package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"main/internal/merkle"
	"main/internal/protocol"
	"main/internal/transport"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CLI représente l'interface en ligne de commande
type CLI struct {
	Server    *transport.Server
	ServerUDP *net.UDPAddr
	reader    *bufio.Reader
}

// NewCLI crée une nouvelle interface CLI
func NewCLI(server *transport.Server, serverUDP *net.UDPAddr) *CLI {
	return &CLI{
		Server:    server,
		ServerUDP: serverUDP,
		reader:    bufio.NewReader(os.Stdin),
	}
}

// Run lance la boucle principale du CLI
func (c *CLI) Run() {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("  🌐 Client P2P - Système de fichiers distribué")
	fmt.Println(strings.Repeat("=", 50))

	for {
		c.showMenu()
		choice := c.readLine("Choix: ")

		switch strings.TrimSpace(choice) {
		case "1":
			c.listPeers()
		case "2":
			c.connectToPeer()
		case "3":
			c.explorePeer()
		case "4":
			c.downloadFile()
		case "5":
			c.showConnectedPeers()
		case "6":
			c.showMyFiles()
		case "7":
			c.showDownloadsFolder()
		case "0", "q", "quit", "exit":
			fmt.Println("\n👋 Fermeture en cours...")
			c.Server.Stop()
			fmt.Println("✅ Au revoir!")
			return
		default:
			fmt.Println("❌ Choix invalide")
		}
	}
}

func (c *CLI) showMenu() {
	fmt.Println("\n┌─────────────────────────────────┐")
	fmt.Println("│           MENU PRINCIPAL        │")
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

func (c *CLI) readLine(prompt string) string {
	fmt.Print(prompt)
	line, _ := c.reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// waitForEnter attend que l'utilisateur appuie sur Entrée
func (c *CLI) waitForEnter() {
	fmt.Print("\n⏎ Appuyez sur Entrée pour continuer...")
	c.reader.ReadString('\n')
}

// parseHexHash parse une chaîne hexadécimale en hash [32]byte
// Accepte les formats: "abc123...", "0xabc123...", avec ou sans espaces
func parseHexHash(input string) ([32]byte, error) {
	var hash [32]byte

	// Nettoyer l'entrée
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, " ", "")
	input = strings.ReplaceAll(input, "\t", "")

	// Supprimer le préfixe "0x" si présent
	input = strings.TrimPrefix(input, "0x")
	input = strings.TrimPrefix(input, "0X")

	// Supprimer les "..." à la fin (hash tronqué affiché)
	if idx := strings.Index(input, "."); idx != -1 {
		input = input[:idx]
	}

	// Convertir en minuscules
	input = strings.ToLower(input)

	// Vérifier la longueur
	if len(input) < 64 {
		return hash, fmt.Errorf("hash trop court (%d chars, besoin de 64). Hash reçu: %s", len(input), input)
	}

	// Prendre les 64 premiers caractères
	input = input[:64]

	// Décoder l'hexadécimal
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return hash, fmt.Errorf("hash invalide (caractères non-hex): %v", err)
	}

	copy(hash[:], decoded)
	return hash, nil
}

// 1. Lister les peers disponibles sur le serveur
func (c *CLI) listPeers() {
	fmt.Println("\n📡 Récupération de la liste des peers...")

	peers, err := transport.GetListPeers()
	if err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
		return
	}

	if len(peers) == 0 {
		fmt.Println("Aucun peer enregistré")
		return
	}

	fmt.Printf("\n📋 %d peers disponibles:\n", len(peers))
	fmt.Println(strings.Repeat("-", 40))
	for i, peer := range peers {
		fmt.Printf("  %2d. %s\n", i+1, peer)
	}
	fmt.Println(strings.Repeat("-", 40))
	c.waitForEnter()
}

// 2. Se connecter à un peer avec NAT hole punching
func (c *CLI) connectToPeer() {
	name := c.readLine("\nNom du peer: ")
	if name == "" {
		return
	}

	// Récupérer les adresses
	addrStr, err := transport.GetAddr(name)
	if err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
		return
	}

	// Parser les adresses
	var peerAddrs []*net.UDPAddr
	for _, a := range strings.Split(strings.TrimSpace(addrStr), "\n") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		if addr, err := net.ResolveUDPAddr("udp", a); err == nil {
			peerAddrs = append(peerAddrs, addr)
			ipType := "IPv4"
			if addr.IP.To4() == nil {
				ipType = "IPv6"
			}
			fmt.Printf("  📍 %s [%s]\n", a, ipType)
		}
	}

	if len(peerAddrs) == 0 {
		fmt.Printf("❌ Aucune adresse valide pour %s\n", name)
		c.waitForEnter()
		return
	}

	fmt.Println("\n🔗 Connexion en cours...")

	// Première phase: tentatives directes
	connected := c.tryDirectConnect(peerAddrs, name, 3)

	// Deuxième phase: NAT traversal si échec
	if !connected {
		fmt.Println("↪️  Tentative NAT traversal via serveur...")
		c.sendNatTraversal(peerAddrs)
		time.Sleep(500 * time.Millisecond) // Laisser le temps au NAT de s'ouvrir
		connected = c.tryDirectConnect(peerAddrs, name, 5)
	}

	if connected {
		fmt.Printf("✅ Connecté à %s\n", name)
	} else {
		fmt.Printf("❌ Impossible de se connecter à %s\n", name)
		fmt.Println("   💡 Astuce: demandez à l'autre peer de se connecter à vous")
	}

	c.waitForEnter()
}

// tryDirectConnect tente une connexion directe
func (c *CLI) tryDirectConnect(addrs []*net.UDPAddr, name string, maxRetries int) bool {
	for i := 0; i < maxRetries; i++ {
		for _, addr := range addrs {
			transport.SendHello(c.Server.Conn, addr, c.Server.MyName, c.Server.PrivKey)
		}
		time.Sleep(300 * time.Millisecond)
		if _, ok := c.Server.PeerManager.Get(name); ok {
			return true
		}
	}
	return false
}

// sendNatTraversal envoie les requêtes NAT traversal
func (c *CLI) sendNatTraversal(targetAddrs []*net.UDPAddr) {
	for _, targetAddr := range targetAddrs {
		var serverAddr *net.UDPAddr
		if targetAddr.IP.To4() != nil {
			serverAddr, _ = net.ResolveUDPAddr("udp", protocol.ServerUDPv4)
		} else {
			serverAddr, _ = net.ResolveUDPAddr("udp", protocol.ServerUDPv6)
		}
		if serverAddr != nil {
			transport.SendNatTraversalRequest(c.Server.Conn, serverAddr, targetAddr, c.Server.PrivKey)
		}
	}
}

func (c *CLI) explorePeer() {
	// Afficher les peers connectés
	connected := c.Server.PeerManager.List()
	if len(connected) == 0 {
		fmt.Println("\n❌ Aucun peer connecté. Utilisez l'option 2 d'abord.")
		return
	}

	fmt.Println("\n📡 Peers connectés:")
	for i, name := range connected {
		fmt.Printf("  %d. %s\n", i+1, name)
	}

	choice := c.readLine("\nNuméro du peer (ou nom): ")
	var peerName string

	// Si c'est un nombre, utiliser l'index
	if idx, err := strconv.Atoi(choice); err == nil && idx > 0 && idx <= len(connected) {
		peerName = connected[idx-1]
	} else {
		peerName = choice
	}

	peerInfo, ok := c.Server.PeerManager.Get(peerName)
	if !ok {
		fmt.Printf("❌ Peer %s non connecté\n", peerName)
		return
	}

	// Demander le RootHash
	fmt.Printf("\n🔍 Demande du hash racine à %s...\n", peerName)
	transport.SendRootRequest(c.Server.Conn, peerInfo.Addr)

	// Attendre la réponse
	fmt.Println("   En attente de la réponse (regardez les logs)...")
	time.Sleep(2 * time.Second)

	// Demander le hash à explorer
	fmt.Println("\n📋 Copiez le hash racine affiché ci-dessus (ou entrez un autre hash)")
	hashStr := c.readLine("Hash à explorer (ou 'skip'): ")
	if hashStr == "skip" || hashStr == "" {
		c.waitForEnter()
		return
	}

	hash, err := parseHexHash(hashStr)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		c.waitForEnter()
		return
	}

	// Télécharger automatiquement l'arborescence
	fmt.Println("\n📥 Téléchargement de l'arborescence en cours...")
	downloader := transport.NewDownloader(c.Server, peerInfo.Addr)
	c.Server.OnDatumReceived = func(h [32]byte, datum []byte) {
		downloader.NotifyReceived(h, datum)
	}
	downloader.DownloadTree(hash)
	c.Server.OnDatumReceived = nil

	// Afficher l'arborescence
	fmt.Println("\n📂 Arborescence:")
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("🌳 Racine: %x\n\n", hash)
	c.printTreeDetailed(hash, "", "", true)
	fmt.Println(strings.Repeat("─", 70))

	c.waitForEnter()
}

// 4. Télécharger un fichier
func (c *CLI) downloadFile() {
	// Afficher les peers connectés
	connected := c.Server.PeerManager.List()
	if len(connected) == 0 {
		fmt.Println("\n❌ Aucun peer connecté. Utilisez l'option 2 d'abord.")
		return
	}

	fmt.Println("\n📡 Peers connectés:")
	for i, name := range connected {
		fmt.Printf("  %d. %s\n", i+1, name)
	}

	choice := c.readLine("\nNuméro du peer: ")
	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(connected) {
		fmt.Println("❌ Choix invalide")
		return
	}

	peerName := connected[idx-1]
	peerInfo, _ := c.Server.PeerManager.Get(peerName)

	// Demander le hash à télécharger
	hashStr := c.readLine("Hash du datum (hex, ou 'root' pour la racine): ")

	var hash [32]byte
	if hashStr == "root" || hashStr == "" {
		// Demander le hash racine au peer
		fmt.Printf("🔍 Demande du hash racine à %s...\n", peerName)
		transport.SendRootRequest(c.Server.Conn, peerInfo.Addr)
		fmt.Println("   En attente de la réponse...")
		time.Sleep(2 * time.Second)

		// Vérifier si on a reçu le root hash dans le cache
		rootHashStr := c.readLine("Hash racine reçu (copier-coller): ")
		if rootHashStr == "" {
			fmt.Println("❌ Aucun hash fourni")
			c.waitForEnter()
			return
		}
		hash, err = parseHexHash(rootHashStr)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			c.waitForEnter()
			return
		}
	} else {
		// Parser le hash hex
		hash, err = parseHexHash(hashStr)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			c.waitForEnter()
			return
		}
	}

	// Téléchargement direct sur disque
	c.downloadToDisk(peerName, peerInfo.Addr, hash)
	c.waitForEnter()
}

// downloadToDisk télécharge directement sur le disque
func (c *CLI) downloadToDisk(peerName string, peerAddr *net.UDPAddr, hash [32]byte) {
	safeName := sanitizeFolderName(peerName)
	baseDir := filepath.Join("downloads", safeName)

	fmt.Printf("\n📂 Destination: %s\n", baseDir)

	downloader := transport.NewDiskDownloader(c.Server, peerAddr, baseDir)
	c.Server.OnDatumReceived = func(h [32]byte, datum []byte) {
		downloader.NotifyReceived(h, datum)
	}

	if err := downloader.DownloadToDisk(hash); err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
	}

	c.Server.OnDatumReceived = nil
}

// sanitizeFolderName nettoie un nom pour l'utiliser comme dossier
func sanitizeFolderName(name string) string {
	// Remplacer les caractères problématiques
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(name)
}

// 5. Afficher les peers connectés
func (c *CLI) showConnectedPeers() {
	connected := c.Server.PeerManager.List()

	fmt.Println("\n🔗 Peers connectés:")
	fmt.Println(strings.Repeat("-", 50))

	if len(connected) == 0 {
		fmt.Println("  Aucun peer connecté")
	} else {
		for _, name := range connected {
			info, _ := c.Server.PeerManager.Get(name)
			fmt.Printf("  • %s\n", name)
			fmt.Printf("    Adresse: %s\n", info.Addr)
			fmt.Printf("    Dernière activité: %s\n", info.LastSeen.Format("15:04:05"))
		}
	}
	fmt.Println(strings.Repeat("-", 50))
	c.waitForEnter()
}

// 6. Afficher mes fichiers partagés
func (c *CLI) showMyFiles() {
	fmt.Println("\n📁 Mes fichiers partagés:")
	fmt.Println(strings.Repeat("─", 70))

	if c.Server.RootHash == [32]byte{} {
		fmt.Println("  Aucun fichier partagé")
		fmt.Println(strings.Repeat("─", 70))
		c.waitForEnter()
		return
	}

	fmt.Printf("  Hash racine: %x\n", c.Server.RootHash)
	fmt.Printf("  Datums dans le store: %d\n", c.Server.MerkleStore.Len())

	// Afficher l'arborescence
	fmt.Println("\n  Arborescence:")
	c.printTreeDetailedLocal(c.Server.RootHash, "  ", "", true)

	fmt.Println(strings.Repeat("─", 70))
	c.waitForEnter()
}

// printTreeDetailedLocal affiche l'arborescence de nos fichiers locaux
func (c *CLI) printTreeDetailedLocal(hash [32]byte, prefix string, name string, isLast bool) {
	datum, ok := c.Server.MerkleStore.Get(hash)
	if !ok {
		return
	}

	connector := "├── "
	if isLast {
		connector = "└── "
	}

	nodeType, data := merkle.ParseDatum(datum)

	childPrefix := prefix
	if name != "" {
		if isLast {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "│   "
		}
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(data)
		if name != "" {
			fmt.Printf("%s%s📁 %s/ [Dir, %d entrées, %x...]\n", prefix, connector, name, len(entries), hash[:8])
		} else {
			fmt.Printf("%s📁 / [Dir, %d entrées, %x...]\n", prefix, len(entries), hash[:8])
		}
		for i, entry := range entries {
			entryName := merkle.GetEntryName(entry)
			c.printTreeDetailedLocal(entry.Hash, childPrefix, entryName, i == len(entries)-1)
		}

	case merkle.TypeBigDirectory:
		hashes := merkle.ParseBigHashes(data)
		if name != "" {
			fmt.Printf("%s%s📁 %s/ [BigDir, %d parties, %x...]\n", prefix, connector, name, len(hashes), hash[:8])
		} else {
			fmt.Printf("%s📁 / [BigDir, %d parties, %x...]\n", prefix, len(hashes), hash[:8])
		}
		for i, h := range hashes {
			c.printTreeDetailedLocal(h, childPrefix, "", i == len(hashes)-1)
		}

	case merkle.TypeChunk:
		sizeStr := formatSize(len(data))
		if name != "" {
			fmt.Printf("%s%s📄 %s [Chunk, %s, %x...]\n", prefix, connector, name, sizeStr, hash[:8])
		} else {
			fmt.Printf("%s%s📄 [Chunk, %s, %x...]\n", prefix, connector, sizeStr, hash[:8])
		}

	case merkle.TypeBig:
		hashes := merkle.ParseBigHashes(data)
		totalSize := c.calculateBigSizeLocal(hash)
		sizeStr := formatSize(totalSize)
		if name != "" {
			fmt.Printf("%s%s📄 %s [Big, %s, %d parties, %x...]\n", prefix, connector, name, sizeStr, len(hashes), hash[:8])
		} else {
			fmt.Printf("%s%s📄 [Big, %s, %d parties, %x...]\n", prefix, connector, sizeStr, len(hashes), hash[:8])
		}
	}
}

// calculateBigSizeLocal calcule la taille d'un Big file local
func (c *CLI) calculateBigSizeLocal(hash [32]byte) int {
	datum, ok := c.Server.MerkleStore.Get(hash)
	if !ok {
		return 0
	}
	nodeType, data := merkle.ParseDatum(datum)

	switch nodeType {
	case merkle.TypeChunk:
		return len(data)
	case merkle.TypeBig:
		total := 0
		hashes := merkle.ParseBigHashes(data)
		for _, h := range hashes {
			total += c.calculateBigSizeLocal(h)
		}
		return total
	}
	return 0
}

// 7. Ouvrir le dossier downloads
func (c *CLI) showDownloadsFolder() {
	fmt.Println("\n📂 Dossier downloads:")
	fmt.Println(strings.Repeat("─", 70))

	// Vérifier si le dossier existe
	if _, err := os.Stat("downloads"); os.IsNotExist(err) {
		fmt.Println("  Aucun téléchargement effectué")
		fmt.Println("  Utilisez l'option 4 pour télécharger des fichiers")
		fmt.Println(strings.Repeat("─", 70))
		c.waitForEnter()
		return
	}

	// Lister les dossiers de peers
	entries, err := os.ReadDir("downloads")
	if err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
		c.waitForEnter()
		return
	}

	if len(entries) == 0 {
		fmt.Println("  Dossier downloads vide")
		fmt.Println(strings.Repeat("─", 70))
		c.waitForEnter()
		return
	}

	// Calculer les stats pour chaque peer
	fmt.Printf("  %d peer(s) téléchargé(s):\n\n", len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		peerPath := filepath.Join("downloads", entry.Name())
		fileCount, totalSize := c.countFilesInDir(peerPath)
		sizeStr := formatSizeInt64(totalSize)
		fmt.Printf("  📁 %s\n", entry.Name())
		fmt.Printf("     └── %d fichier(s), %s\n", fileCount, sizeStr)
	}

	fmt.Println(strings.Repeat("─", 70))
	fmt.Println("\n📍 Emplacement: ./downloads/")
	c.waitForEnter()
}

// countFilesInDir compte les fichiers dans un dossier
func (c *CLI) countFilesInDir(path string) (int, int64) {
	var count int
	var size int64
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			count++
			size += info.Size()
		}
		return nil
	})
	return count, size
}

// formatSizeInt64 formate une taille en bytes
func formatSizeInt64(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
}

// printTreeDetailed affiche une arborescence détaillée avec caractères box-drawing
func (c *CLI) printTreeDetailed(hash [32]byte, prefix string, name string, isLast bool) {
	// Récupérer le datum (d'abord dans Downloads, puis dans MerkleStore)
	datum, ok := c.Server.Downloads.Get(hash)
	if !ok {
		datum, ok = c.Server.MerkleStore.Get(hash)
	}

	// Caractères pour l'arborescence
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	if !ok {
		// Datum non disponible
		if name != "" {
			fmt.Printf("%s%s❓ %s (non téléchargé)\n", prefix, connector, name)
			fmt.Printf("%s    Hash: %x\n", prefix, hash)
		} else {
			fmt.Printf("%s%s❓ (non téléchargé)\n", prefix, connector)
			fmt.Printf("%s    Hash: %x\n", prefix, hash)
		}
		return
	}

	nodeType, data := merkle.ParseDatum(datum)

	// Calculer le nouveau préfixe pour les enfants
	childPrefix := prefix
	if name != "" {
		if isLast {
			childPrefix = prefix + "    "
		} else {
			childPrefix = prefix + "│   "
		}
	}

	switch nodeType {
	case merkle.TypeDirectory:
		entries := merkle.ParseDirectoryEntries(data)
		if name != "" {
			fmt.Printf("%s%s📁 %s/ [Dir, %d entrées] %x\n", prefix, connector, name, len(entries), hash)
		} else {
			fmt.Printf("%s📁 / [Dir, %d entrées] %x\n", prefix, len(entries), hash)
		}
		for i, entry := range entries {
			entryName := merkle.GetEntryName(entry)
			c.printTreeDetailed(entry.Hash, childPrefix, entryName, i == len(entries)-1)
		}

	case merkle.TypeBigDirectory:
		hashes := merkle.ParseBigHashes(data)
		if name != "" {
			fmt.Printf("%s%s📁 %s/ [BigDir, %d parties] %x\n", prefix, connector, name, len(hashes), hash)
		} else {
			fmt.Printf("%s📁 / [BigDir, %d parties] %x\n", prefix, len(hashes), hash)
		}
		for i, h := range hashes {
			c.printTreeDetailed(h, childPrefix, "", i == len(hashes)-1)
		}

	case merkle.TypeChunk:
		sizeStr := formatSize(len(data))
		preview := ""
		if len(data) > 0 && isPrintable(data[:min(len(data), 30)]) {
			preview = fmt.Sprintf(" \"%s\"", string(data[:min(len(data), 30)]))
			if len(data) > 30 {
				preview = preview[:len(preview)-1] + "...\""
			}
		}
		if name != "" {
			fmt.Printf("%s%s📄 %s [Chunk, %s]%s %x\n", prefix, connector, name, sizeStr, preview, hash)
		} else {
			fmt.Printf("%s%s📄 [Chunk, %s]%s %x\n", prefix, connector, sizeStr, preview, hash)
		}

	case merkle.TypeBig:
		hashes := merkle.ParseBigHashes(data)
		// Calculer la taille totale si on a tous les chunks
		totalSize := c.calculateBigSize(hash)
		sizeStr := "?"
		if totalSize > 0 {
			sizeStr = formatSize(totalSize)
		}
		if name != "" {
			fmt.Printf("%s%s📄 %s [Big, %s, %d parties] %x\n", prefix, connector, name, sizeStr, len(hashes), hash)
		} else {
			fmt.Printf("%s%s📄 [Big, %s, %d parties] %x\n", prefix, connector, sizeStr, len(hashes), hash)
		}
	}
}

// calculateBigSize calcule la taille totale d'un Big file
func (c *CLI) calculateBigSize(hash [32]byte) int {
	datum, ok := c.Server.Downloads.Get(hash)
	if !ok {
		return 0
	}
	nodeType, data := merkle.ParseDatum(datum)

	switch nodeType {
	case merkle.TypeChunk:
		return len(data)
	case merkle.TypeBig:
		total := 0
		hashes := merkle.ParseBigHashes(data)
		for _, h := range hashes {
			size := c.calculateBigSize(h)
			if size == 0 {
				return 0 // Un chunk manque
			}
			total += size
		}
		return total
	}
	return 0
}

// formatSize formate une taille en bytes de façon lisible
func formatSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}

// isPrintable vérifie si les données sont du texte affichable
func isPrintable(data []byte) bool {
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

// min retourne le minimum de deux entiers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
