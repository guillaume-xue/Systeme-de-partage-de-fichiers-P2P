package transport

import (
	"fmt"
	"main/internal/protocol"
	"net"
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
	id, msgType, _, body, signature, err := protocol.DecodeMessages(data)
	if err != nil {
		fmt.Println("Erreur décodage message:", err)
		return
	}

	switch msgType {
	case protocol.Hello:
		processHello(conn, body, signature, remoteAddr, id)
	case protocol.HelloReply:
		processHelloReply(body, signature, remoteAddr)
	case protocol.Ping:
		fmt.Println("Ping reçu")
		// TODO: Répondre avec Ok
	case protocol.Ok:
		fmt.Println("Ok reçu")
	default:
		fmt.Printf("Message type %d reçu\n", msgType)
	}
}

func processHello(conn *net.UDPConn, body []byte, signature []byte, addr *net.UDPAddr, msgID uint32) {
	if len(body) < 4 {
		fmt.Println("Hello invalide (pas d'extensions)")
		return
	}

	nameBytes := body[4:]
	remoteName := string(nameBytes)

	fmt.Printf("HELLO reçu de : %s (%s)\n", remoteName, addr)

	if len(signature) != 64 {
		fmt.Println("Hello non signé ! (Devrait être rejeté)")
	} else {
		fmt.Println("Signature présente.")
		SendHandshake(conn, addr, msgID, protocol.HelloReply)
	}
}

func processHelloReply(body []byte, signature []byte, addr *net.UDPAddr) {
	if len(body) < 4 {
		fmt.Println("HelloReply invalide")
		return
	}

	nameBytes := body[4:]
	remoteName := string(nameBytes)

	fmt.Printf("HELLO REPLY reçu de : %s (%s)\n", remoteName, addr)

	if len(signature) != 64 {
		fmt.Println("HelloReply non signé !")
	} else {
		fmt.Println("Signature présente.")
	}
}
