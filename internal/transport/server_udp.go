package transport

import (
	"bufio"
	"fmt"
	"io"
	"main/internal/merkle"
	"main/internal/protocol"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type serverUDP struct {
	Conn4 *net.UDPConn
	Conn6 *net.UDPConn

	mutex   sync.Mutex
	timerOn bool
	timer   *time.Ticker

	LocalMerkle    *merkle.Merkle
	DownloadMerkle *merkle.Merkle
}

func (s *serverUDP) init() {

	s.LocalMerkle = merkle.NewMerkle()
	s.DownloadMerkle = merkle.NewMerkle()

	s.timerOn = false
	s.timer = nil

	addr4, _ := net.ResolveUDPAddr("udp4", ":8080")
	addr6, _ := net.ResolveUDPAddr("udp6", ":8080")

	var err4, err6 error
	s.Conn4, err4 = net.ListenUDP("udp4", addr4)
	if err4 != nil {
		fmt.Println("Erreur IPv4:", err4)
	} else {
		fmt.Println("Serveur UDP IPv4 démarré sur :8080")
		go ListenLoop(s, "udp4")
	}

	s.Conn6, err6 = net.ListenUDP("udp6", addr6)
	if err6 != nil {
		fmt.Println("Erreur IPv6:", err6)
	} else {
		fmt.Println("Serveur UDP IPv6 démarré sur :8080")
		go ListenLoop(s, "udp6")
	}
}

func (s *serverUDP) StartPing() {
	s.mutex.Lock()
	s.timerOn = true
	defer s.mutex.Unlock()
}

func (s *serverUDP) pingLoop() {
	s.mutex.Lock()
	timerOn := s.timerOn
	s.mutex.Unlock()

	if !timerOn {
		return
	}

	ticker := time.NewTicker(2 * time.Minute)
	s.mutex.Lock()
	s.timer = ticker
	s.mutex.Unlock()

	for {
		<-ticker.C
		serverAddr4, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP4)
		serverAddr6, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP6)
		if s.Conn4 != nil {
			SendPacket(s.Conn4, serverAddr4, uint32(0), protocol.Ping, []byte{})
		}
		if s.Conn6 != nil {
			SendPacket(s.Conn6, serverAddr6, uint32(0), protocol.Ping, []byte{})
		}
	}
}

func ListenLoop(s *serverUDP, option string) {
	buffer := make([]byte, 4096)
	for {
		var conn *net.UDPConn
		if option == "udp4" {
			conn = s.Conn4
		} else {
			conn = s.Conn6
		}
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Erreur lecture:", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		go handlePacket(s, remoteAddr, data, option)
		go s.pingLoop()
	}
}

func handlePacket(s *serverUDP, remoteAddr *net.UDPAddr, data []byte, option string) {
	_, msgType, _, err := protocol.DecodeHeader(data)
	if err != nil {
		fmt.Println("Erreur décodage header:", err)
		return
	}
	var conn *net.UDPConn
	if option == "udp4" {
		conn = s.Conn4
	} else {
		conn = s.Conn6
	}

	switch msgType {
	case protocol.Hello:
		processHello(conn, remoteAddr, data)
	case protocol.HelloReply:
		processHelloReply(conn, remoteAddr, data)
	case protocol.RootRequest:
		processRootRequest(conn, remoteAddr, data)
	case protocol.RootReply:
		processRootReply(s, conn, remoteAddr, data)
	case protocol.Ping:
		fmt.Println("Ping reçu")
	case protocol.Ok:
		fmt.Println("Ok reçu")
	case protocol.DatumRequest:
		fmt.Println("DatumRequest reçu")
	case protocol.Datum:
		processDatum(s, conn, remoteAddr, data)
	case protocol.NoDatum:
		fmt.Println("NoDatum reçu")
	case protocol.Timeout:
		fmt.Println("Timeout reçu")
	case protocol.Error:
		processErreur(conn, remoteAddr, data)
	default:
		fmt.Printf("Message type %d reçu\n", msgType)
	}
}

func processHello(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	msgID, _, _, _, remoteName, signature, err := protocol.DecodeHandshakeMessage(data)
	if err != nil {
		fmt.Println("Erreur décodage Hello:", err)
		return
	}
	if len(remoteName) < 1 {
		fmt.Println("Hello invalide (nom manquant)")
		return
	}
	remoteNameStr := string(remoteName)

	fmt.Printf("HELLO reçu de : %s (%s)\n\n", remoteNameStr, addr)

	if len(signature) != 64 {
		fmt.Println("Hello non signé ! (Devrait être rejeté)")
	} else {
		fmt.Println("Signature présente.")
		time.Sleep(1 * time.Second)
		SendPacket(conn, addr, msgID, protocol.HelloReply, []byte{})
	}
}

func processHelloReply(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	_, _, _, _, remoteName, signature, err := protocol.DecodeHandshakeMessage(data)
	if err != nil {
		fmt.Println("Erreur décodage HelloReply:", err)
		return
	}
	if len(remoteName) < 1 {
		fmt.Println("HelloReply invalide (nom manquant)")
		return
	}
	remoteNameStr := string(remoteName)

	fmt.Printf("HELLO REPLY reçu de : %s (%s)\n\n", remoteNameStr, addr)

	if len(signature) != 64 {
		fmt.Println("HelloReply non signé !")
	} else {
		fmt.Println("Signature présente.")
	}
}

func processRootRequest(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	id, _, _, hash, err := protocol.DecodeRootAndData(data)
	if err != nil {
		fmt.Println("Erreur décodage RootRequest:", err)
		return
	}
	fmt.Printf("ROOT REQUEST reçu de %s pour le hash : %x\n", addr, hash)
	SendPacket(conn, addr, id, protocol.RootReply, []byte{})
}

func processRootReply(s *serverUDP, conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	id, _, _, hash, err := protocol.DecodeRootAndData(data)
	if err != nil {
		fmt.Println("Erreur décodage RootReply:", err)
		return
	}
	fmt.Printf("ROOT REPLY reçu (ID:%d) pour le hash : %x\n", id, hash)
	s.DownloadMerkle.Clean()
}

func processDatum(s *serverUDP, conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	_, _, _, hash, value, _, err := protocol.DecodeDatum(data)
	if err != nil {
		fmt.Println("Erreur décodage Datum:", err)
		return
	}
	fmt.Printf("DATUM reçu pour le hash : %x\n", hash)
	child, err := s.DownloadMerkle.ParseValue(value)
	if err != nil {
		fmt.Println("Erreur parsing Datum:", err)
		return
	}
	if len(child) > 0 {
		nodeType := value[0]
		switch nodeType {
		case merkle.TypeDirectory, merkle.TypeBigDirectory:
			fmt.Println("Contenu du Directory/BigDirectory:")
		case merkle.TypeBig:
			fmt.Println("Contenu du fichier fragmenté (TypeBig):")
		}
		for _, entry := range child {
			fmt.Printf(" - Entrée: %x\n", entry)
			SendPacket(conn, addr, uint32(0), protocol.DatumRequest, entry)
		}
	}
}

func processErreur(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	_, _, _, errMsg, _, err := protocol.DecodeMessages(data)
	if err != nil {
		fmt.Println("Erreur décodage Error:", err)
		return
	}
	fmt.Printf("ERROR reçu de %s : %s\n", addr, string(errMsg))
}

func (s *serverUDP) WriteFileContent(nodeHash []byte, writer io.Writer) error {
	data, exists := s.DownloadMerkle.GetNode(nodeHash)
	if !exists {
		return fmt.Errorf("morceau manquant : %x", nodeHash)
	}

	nodeType := data[0]
	switch nodeType {
	case merkle.TypeChunk: // 0
		_, err := writer.Write(data[1:]) // On écrit sans le header
		return err
	case merkle.TypeBig: // 2
		hashes, _ := merkle.ParseBig(data[1:])
		for _, h := range hashes {
			if err := s.WriteFileContent(h, writer); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("type fichier invalide: %d", nodeType)
	}
}

func (s *serverUDP) CollectDirEntries(nodeHash []byte) ([]merkle.DirEntry, error) {
	data, exists := s.DownloadMerkle.GetNode(nodeHash)
	if !exists {
		return nil, fmt.Errorf("dossier manquant : %x (téléchargement peut-être incomplet, attendez plus longtemps)", nodeHash)
	}

	nodeType := data[0]
	var allEntries []merkle.DirEntry

	switch nodeType {
	case merkle.TypeDirectory: // 1
		return merkle.ParseDirectory(data[1:])
	case merkle.TypeBigDirectory: // 4
		hashes, _ := merkle.ParseBigDirectory(data[1:])
		for _, h := range hashes {
			subEntries, err := s.CollectDirEntries(h)
			if err != nil {
				return nil, err
			}
			allEntries = append(allEntries, subEntries...)
		}
		return allEntries, nil
	default:
		return nil, fmt.Errorf("ce n'est pas un dossier : %d", nodeType)
	}
}

func (s *serverUDP) CheckTreeComplete(nodeHash []byte, visited map[string]bool) (bool, []string) {
	hashStr := fmt.Sprintf("%x", nodeHash)

	if visited[hashStr] {
		return true, nil
	}
	visited[hashStr] = true

	data, exists := s.DownloadMerkle.GetNode(nodeHash)
	if !exists {
		return false, []string{hashStr}
	}

	if len(data) == 0 {
		return false, []string{hashStr}
	}

	nodeType := data[0]
	var missing []string

	switch nodeType {
	case merkle.TypeChunk:
		return true, nil

	case merkle.TypeBig:
		hashes, _ := merkle.ParseBig(data[1:])
		for _, h := range hashes {
			complete, missingNodes := s.CheckTreeComplete(h, visited)
			if !complete {
				missing = append(missing, missingNodes...)
			}
		}

	case merkle.TypeDirectory:
		entries, _ := merkle.ParseDirectory(data[1:])
		for _, entry := range entries {
			complete, missingNodes := s.CheckTreeComplete(entry.Hash, visited)
			if !complete {
				missing = append(missing, missingNodes...)
			}
		}

	case merkle.TypeBigDirectory:
		hashes, _ := merkle.ParseBigDirectory(data[1:])
		for _, h := range hashes {
			complete, missingNodes := s.CheckTreeComplete(h, visited)
			if !complete {
				missing = append(missing, missingNodes...)
			}
		}
	}

	if len(missing) > 0 {
		return false, missing
	}
	return true, nil
}

func (s *serverUDP) ReconstructTree(nodeHash []byte, targetPath string) error {

	data, exists := s.DownloadMerkle.GetNode(nodeHash)
	if !exists {
		return fmt.Errorf("nœud racine manquant : %x", nodeHash)
	}
	nodeType := data[0]

	if nodeType == merkle.TypeDirectory || nodeType == merkle.TypeBigDirectory {
		fmt.Printf("Création du dossier : %s\n", targetPath)

		err := os.MkdirAll(targetPath, 0755)
		if err != nil {
			return err
		}

		entries, err := s.CollectDirEntries(nodeHash)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			childPath := filepath.Join(targetPath, entry.Name)
			err := s.ReconstructTree(entry.Hash, childPath)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if nodeType == merkle.TypeChunk || nodeType == merkle.TypeBig {
		fmt.Printf("Écriture du fichier : %s\n", targetPath)
		f, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer f.Close()
		return s.WriteFileContent(nodeHash, f)
	}

	return fmt.Errorf("type de nœud inconnu : %d", nodeType)
}

func RunServerUDP() {

	s := &serverUDP{}
	s.init()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Entrez du texte (Ctrl+C pour quitter):")

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		command := parts[0]

		switch command {
		case "addr":
			if len(parts) < 2 {
				fmt.Println("Usage: addr <nom>")
				break
			}
			name := parts[1]
			addr, err := GetAddr(name)
			if err != nil {
				fmt.Printf("Erreur GetAddr: %v\n", err)
			} else {
				fmt.Printf("Adresse de %s : %s\n", name, addr)
			}
		case "list":
			list, _ := GetListPeers()
			for _, peer := range list {
				fmt.Println("Peer:", peer)
			}
		case "key":
			if len(parts) < 2 {
				fmt.Println("Usage: key <nom>")
				break
			}
			name := parts[1]
			key, err := GetKey(name)
			if err != nil {
				fmt.Printf("Erreur GetKey: %v\n", err)
			} else {
				fmt.Printf("Clé publique de %s : %x\n", name, key)
			}
		case "register":
			RegisterClient(s.Conn4, s.Conn6)
			s.StartPing()
		case "help":
			fmt.Println("Commandes disponibles :")
			fmt.Println("  register - S'enregistrer sur le serveur")
			fmt.Println("  rootrequest <ipv4|ipv6> <nom> - Demander le root hash")
			fmt.Println("  datumrequest <ipv4|ipv6> <hash> - Demander un datum")
			fmt.Println("  count - Afficher le nombre de nœuds téléchargés")
			fmt.Println("  print - Afficher tous les nœuds")
			fmt.Println("  construct <hash> - Reconstruire l'arbre")
			fmt.Println("  addr <nom> - Obtenir l'adresse d'un peer")
			fmt.Println("  list - Lister les peers")
			fmt.Println("  key <nom> - Obtenir la clé publique d'un peer")
		case "rootrequest":
			if len(parts) < 2 {
				fmt.Println("Usage: rootrequest <nom>")
				break
			}
			if parts[1] != "ipv4" && parts[1] != "ipv6" {
				fmt.Println("Usage: rootrequest <ipv4|ipv6>")
				break
			}
			if parts[1] == "ipv4" {
				serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP4)
				SendPacket(s.Conn4, serverAddr, uint32(0), protocol.RootRequest, []byte{})
			} else {
				serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP6)
				SendPacket(s.Conn6, serverAddr, uint32(0), protocol.RootRequest, []byte{})
			}
		case "datumrequest":
			if len(parts) < 3 {
				fmt.Println("Usage: datumrequest <ipv4|ipv6> <hash>")
				break
			}
			hashStr := parts[2]
			hash := make([]byte, 32)
			n, err := fmt.Sscanf(hashStr, "%x", &hash)
			if err != nil || n != 1 {
				fmt.Println("Hash invalide.")
				break
			}
			switch parts[1] {
			case "ipv4":
				serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP4)
				SendPacket(s.Conn4, serverAddr, uint32(0), protocol.DatumRequest, hash)
			case "ipv6":
				serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP6)
				SendPacket(s.Conn6, serverAddr, uint32(0), protocol.DatumRequest, hash)
			default:
				fmt.Println("Usage: datumrequest <ipv4|ipv6> <hash>")
			}
		case "print":
			s.DownloadMerkle.PrintAllNodes()
		case "count":
			count := s.DownloadMerkle.Count()
			fmt.Printf("Nombre de nœuds téléchargés : %d\n", count)
		case "construct":
			if len(parts) < 2 {
				fmt.Println("Usage: construct <hash>")
				break
			}
			hashStr := parts[1]
			hash := make([]byte, 32)
			n, err := fmt.Sscanf(hashStr, "%x", &hash)
			if err != nil || n != 1 {
				fmt.Println("Hash invalide.")
				break
			}

			// Vérifier que tous les nœuds sont présents
			fmt.Println("Vérification de la complétude de l'arbre...")
			visited := make(map[string]bool)
			complete, missing := s.CheckTreeComplete(hash, visited)
			if !complete {
				fmt.Printf("⚠️  Téléchargement incomplet ! %d nœuds manquants:\n", len(missing))
				for i, m := range missing {
					if i < 5 {
						fmt.Printf("  - %s\n", m)
					}
				}
				if len(missing) > 5 {
					fmt.Printf("  ... et %d autres\n", len(missing)-5)
				}
				fmt.Println("💡 Attendez que tous les DATUM soient reçus, puis réessayez.")
				break
			}

			fmt.Println("✓ Arbre complet, démarrage de la reconstruction...")
			err = s.ReconstructTree(hash, "Downloads/Reconstructed")
			if err != nil {
				fmt.Println("Erreur reconstruction:", err)
			} else {
				fmt.Println("✓ Reconstruction terminée avec succès !")
			}
		default:
			fmt.Println("Commande non reconnue.")
		}
		fmt.Println("Nouvelle entrée (Ctrl+C pour quitter):")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Erreur lecture:", err)
	}
}
