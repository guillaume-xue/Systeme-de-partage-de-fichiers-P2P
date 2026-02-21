package transport

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"main/internal/config"
	"main/internal/protocol"
	"net"
	"time"
)

var (
	isDualStack bool // IPv6 avec support IPv4 (true) ou IPv4 only (false)
)

// TryConnectWithFallback : JE NE REMERCIE PAS WINDOWS ET LEUR RESTRICTIONS STUPIDE !!!
// 1. On essaie de bind le port local (IPv6 puis IPv4)
// 2. On essaie de contacter le serveur (IPv6 puis IPv4)
func TryConnectWithFallback(name string, privKey *ecdsa.PrivateKey) (*net.UDPConn, *net.UDPAddr, error) {
	var conn *net.UDPConn
	var err error

	// ÉTAPE 1 : Ouvrir le socket local
	// On essaie d'abord le Dual-Stack (IPv6 + IPv4)
	// Note : Sur Windows, il faut configurer le registre pour que [::] écoute aussi IPv4, (QUEL GALERE BORDEL)
	// Merci Go qui semble gérer ça de facon automatique
	fmt.Println("ℹ️️ Ouverture du socket UDP...")

	// Ici on laisse l'OS choisir pour éviter les conflits "Address already in use".
	addrV6, _ := net.ResolveUDPAddr("udp", "[::]:0")
	conn, err = net.ListenUDP("udp", addrV6)

	if err == nil {
		isDualStack = true
		fmt.Printf("   ✅ Socket ouvert en Dual-Stack/IPv6 sur %s\n", conn.LocalAddr())
	} else {
		// Fallback IPv4 pur (réseau très strict ou comme moi wsl sous Windows (émulateur))
		fmt.Println("   ⚠️ Echec IPv6, passage en IPv4 only...")
		addrV4, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		conn, err = net.ListenUDP("udp4", addrV4)
		if err != nil {
			return nil, nil, fmt.Errorf("impossible d'ouvrir un socket: %v", err)
		}
		isDualStack = false
		fmt.Printf("   ✅ Socket ouvert en IPv4 sur %s\n", conn.LocalAddr())
	}

	// ÉTAPE 2 : Handshake avec le serveur
	// On doit déterminer quelle adresse du serveur utiliser
	targets := []string{}

	// Si on est dual stack, on préfère l'IPv6 du serveur
	if isDualStack {
		targets = append(targets, protocol.GetServerUDPv6())
	}
	// On ajoute toujours l'IPv4 en fallback
	targets = append(targets, protocol.GetServerUDPv4())

	for _, targetStr := range targets {
		serverAddr, err := net.ResolveUDPAddr("udp", targetStr)
		if err != nil {
			fmt.Printf("   ⚠️ Adresse serveur invalide (%s): %v\n", targetStr, err)
			continue
		}

		fmt.Printf("ℹ️️ Tentative de connexion au serveur %s...\n", targetStr)

		// Envoi Hello
		helloID, err := SendHello(conn, serverAddr, name, privKey)
		if err != nil {
			fmt.Printf("   ❌ Erreur envoi: %v\n", err)
			continue
		}

		// Attente réponse (bloquant avec timeout court)
		if waitResponse(conn, helloID) {
			fmt.Println("   ✅ Connexion établie !")

			// Si on est en dual stack, on envoie un ping sur l'autre protocole aussi
			// pour que le serveur enregistre nos deux adresses (V4 et V6).
			if isDualStack && targetStr == protocol.GetServerUDPv6() {
				if otherAddr, err := net.ResolveUDPAddr("udp", protocol.GetServerUDPv4()); err == nil {
					SendHello(conn, otherAddr, name, privKey)
				}
			}

			return conn, serverAddr, nil
		}

		fmt.Println("   ❌ Timeout serveur.")
	}

	conn.Close()
	return nil, nil, fmt.Errorf("impossible de joindre le serveur (toutes tentatives échouées)")
}

// waitResponse attend un paquet spécifique pendant la durée configurée
func waitResponse(conn *net.UDPConn, expectedID uint32) bool {
	deadline := time.Now().Add(config.GlobalConfig.Network.HandshakeTimeout)
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, config.GlobalConfig.Network.HandshakeBufferSize)

	for {
		// On calcule le temps restant
		if time.Now().After(deadline) {
			return false // Timeout écoulé
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Si c'est une erreur de timeout réseau, on arrête
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false
			}
			continue
		}

		if n < 5 {
			continue
		}

		// Lecture rapide de l'en-tête (BigEndian Uint32)
		rcvID := binary.BigEndian.Uint32(buf[0:4])
		msgType := buf[4]

		if rcvID == expectedID {
			// On accepte les types de réponse valides
			return msgType == protocol.HelloReply || msgType == protocol.Ok || msgType == protocol.Ping
		}
		// Si ce n'est pas le bon ID, on boucle et on réessaie (tant que le temps n'est pas écoulé)
	}
}

func GetNetworkMode() string {
	if isDualStack {
		return "Dual-Stack (IPv4 + IPv6)"
	}
	return "IPv4 Legacy"
}
