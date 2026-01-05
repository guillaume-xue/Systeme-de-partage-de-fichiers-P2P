package transport

import (
	"bufio"
	"fmt"
	"main/internal/merkle"
	"main/internal/protocol"
	"net"
	"os"
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

	ticker := time.NewTicker(4 * time.Minute)
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
		// TODO: Répondre avec Ok
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
		fmt.Println("Error reçu")
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
		fmt.Println("Contenu du Directory/BigDirectory:")
		for _, entry := range child {
			fmt.Printf(" - Entrée: %x\n", entry)
			SendPacket(conn, addr, uint32(0), protocol.DatumRequest, entry)
		}
	}
	time.Sleep(1 * time.Second)
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
			fmt.Println("Commandes disponibles : addr, list, key, register, help")
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
		default:
			fmt.Println("Commande non reconnue.")
		}
		fmt.Println("Nouvelle entrée (Ctrl+C pour quitter):")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Erreur lecture:", err)
	}
}
