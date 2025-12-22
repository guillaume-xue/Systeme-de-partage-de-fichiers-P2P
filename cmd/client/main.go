package main

import (
	"fmt"
	"main/internal/crypto"
	"main/internal/protocol"
	"main/internal/transport"
	"net"
)

func main() {
	privKey, _ := crypto.LoadOrGenerateKey(protocol.FILENAME)

	localAddr, _ := net.ResolveUDPAddr("udp", ":8080")

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Port UDP 8080 ouvert pour écoute et envoi.")

	go transport.ListenLoop(conn)

	if err := transport.RegisterHTTP(privKey); err != nil {
		fmt.Println("Erreur HTTP:", err)
	}

	serverAddr, _ := net.ResolveUDPAddr("udp", protocol.ServerUDP)
	if err := transport.SendHello(conn, serverAddr, protocol.MyName, privKey); err != nil {
		fmt.Println("Erreur envoi Hello:", err)
	}

	select {}

}
