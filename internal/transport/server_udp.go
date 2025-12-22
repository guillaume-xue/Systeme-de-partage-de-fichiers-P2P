package transport

import (
	"bytes"
	"encoding/binary"
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
	if len(data) < 7 {
		return
	}

	reader := bytes.NewReader(data[:7])
	var msg protocol.Messages

	binary.Read(reader, binary.BigEndian, &msg.ID)
	binary.Read(reader, binary.BigEndian, &msg.Type)
	binary.Read(reader, binary.BigEndian, &msg.Length)

	if len(data) < 7+int(msg.Length) {
		fmt.Println("Paquet corrompu (Body incomplet)")
		return
	}

	body := data[7 : 7+msg.Length]

	var signature []byte
	if len(data) >= 7+int(msg.Length)+64 {
		signature = data[7+int(msg.Length) : 7+int(msg.Length)+64]
	}

	switch msg.Type {
	case protocol.Hello:
		processHello(body, signature, remoteAddr)
	case protocol.HelloReply:
		processHelloReply(body, signature, remoteAddr)
	case protocol.Ping:
		fmt.Println("Ping reçu")
		// TODO: Répondre avec Ok
	case protocol.Ok:
		fmt.Println("Ok reçu")
	default:
		fmt.Printf("Message type %d reçu\n", msg.Type)
	}
}

func processHello(body []byte, signature []byte, addr *net.UDPAddr) {
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
		// TODO: Vérifier la signature
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
