package transport

import (
	"bufio"
	"fmt"
	"main/internal/merkle"
	"main/internal/protocol"
	"net"
	"os"
	"time"
)

func ListenLoop(conn *net.UDPConn) {
	buffer := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Erreur lecture:", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		go handlePacket(conn, remoteAddr, data)
	}
}

func handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	_, msgType, _, err := protocol.DecodeHeader(data)
	if err != nil {
		fmt.Println("Erreur décodage header:", err)
		return
	}

	switch msgType {
	case protocol.Hello:
		processHello(conn, remoteAddr, data)
	case protocol.HelloReply:
		processHelloReply(conn, remoteAddr, data)
	case protocol.RootRequest:
		processRootRequest(conn, remoteAddr, data)
	case protocol.RootReply:
		processRootReply(conn, remoteAddr, data)
	case protocol.Ping:
		fmt.Println("Ping reçu")
		// TODO: Répondre avec Ok
	case protocol.Ok:
		fmt.Println("Ok reçu")
	case protocol.DatumRequest:
		fmt.Println("DatumRequest reçu")
	case protocol.Datum:
		processDatum(data)
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

func processRootReply(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	id, _, _, hash, err := protocol.DecodeRootAndData(data)
	if err != nil {
		fmt.Println("Erreur décodage RootReply:", err)
		return
	}
	fmt.Printf("ROOT REPLY reçu (ID:%d) pour le hash : %x\n", id, hash)
	SendPacket(conn, addr, id, protocol.DatumRequest, hash)
}

func processDatum(data []byte) {
	_, _, _, hash, value, _, err := protocol.DecodeDatum(data)
	if err != nil {
		fmt.Println("Erreur décodage Datum:", err)
		return
	}
	fmt.Printf("DATUM reçu pour le hash : %s\n", string(hash))
	_, err = merkle.ParseValue(value)
	if err != nil {
		fmt.Println("Erreur parsing value:", err)
	}

}

func RunServerUDP() {
	addr4, _ := net.ResolveUDPAddr("udp4", ":8080")
	addr6, _ := net.ResolveUDPAddr("udp6", ":8080")

	conn4, err4 := net.ListenUDP("udp4", addr4)
	if err4 != nil {
		fmt.Println("Erreur IPv4:", err4)
	} else {
		fmt.Println("Serveur UDP IPv4 démarré sur :8080")
		go ListenLoop(conn4)
		defer conn4.Close()
	}

	conn6, err6 := net.ListenUDP("udp6", addr6)
	if err6 != nil {
		fmt.Println("Erreur IPv6:", err6)
	} else {
		fmt.Println("Serveur UDP IPv6 démarré sur :8080")
		go ListenLoop(conn6)
		defer conn6.Close()
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Entrez du texte (Ctrl+C pour quitter):")

	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "GetAddr":
			addr, _ := GetAddr(protocol.MyName)
			fmt.Printf("Adresse de %s : %s\n", protocol.MyName, addr)
		case "List":
			list, _ := GetListPeers()
			for _, peer := range list {
				fmt.Println("Peer:", peer)
			}
		case "GetKey":
			key, _ := GetKey(protocol.MyName)
			fmt.Printf("Clé publique de %s : %x\n", protocol.MyName, key)
		case "Register":
			RegisterClient(conn4, conn6)
		case "Help":
			fmt.Println("Commandes disponibles : GetAddr, List, GetKey, Register, Help")
		case "RootRequest":
			serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP6)
			SendPacket(conn4, serverAddr, uint32(0), protocol.RootRequest, []byte{})
			SendPacket(conn6, serverAddr, uint32(0), protocol.RootRequest, []byte{})
		default:
			fmt.Println("Commande non reconnue.")
		}
		fmt.Println("Nouvelle entrée (Ctrl+C pour quitter):")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Erreur lecture:", err)
	}
}
