package menu

import (
	"fmt"
	"main/internal/config"
	"main/internal/protocol"
	"main/internal/transport"
	"main/internal/utils"
	"net"
	"strings"
	"time"
)

/*
	Logique de connexion aux peers (Direct + NAT Traversal)
*/

// connectToPeer se connecte à un pair (Direct + NAT Traversal)
func (m *InteractiveMenu) connectToPeer(pName string) {
	_, ok := m.server.Manager.Get(pName)
	if ok {
		return // Déjà connecté
	}

	// Récup ip, parser et filtrer
	listAddr, err := transport.GetAddr(pName)
	if err != nil {
		fmt.Printf("Impossible de récupérer les adresses de %s: %v\n", pName, err)
		return
	}
	targets := utils.AddrParserSolver(listAddr)
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
	m.sendDirectConnection(targets, pName, 1)

	// Vérifier quels protocoles ont réussi
	targetIPv4, targetIPv6 := utils.SeparateAddressesByProtocol(targets)
	var remainingTargets []*net.UDPAddr

	peerInfo, exists := m.server.Manager.Get(pName)
	if exists {
		// Vérifier quels protocoles manquent
		hasIPv4, hasIPv6 := false, false
		for _, addrInfo := range peerInfo.Addrs {
			if utils.IsIPv4(addrInfo.Addr) {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}

		// Garder uniquement les protocoles qui ont échoué
		if !hasIPv4 {
			remainingTargets = append(remainingTargets, targetIPv4...)
		}
		if !hasIPv6 {
			remainingTargets = append(remainingTargets, targetIPv6...)
		}
	} else {
		// Aucun protocole n'a réussi
		remainingTargets = targets
	}

	// Phase 2: NAT traversal pour les protocoles qui ont échoué
	if len(remainingTargets) > 0 {
		choixRelais := ""
		if protocol.DebugEnabled {
			fmt.Println("\n--- Choix du relais pour NAT traversal ---")
			fmt.Println("Appuyez sur Entrée (ou tapez 'default') pour utiliser le serveur central")
			fmt.Println("Ou entrez le nom d'un peer connecté pour l'utiliser comme relais")
			choixRelais = m.ask("Relais : ")
			choixRelais = strings.TrimSpace(choixRelais)
		}

		// Configurer les canaux de réception pour chaque adresse restante
		responseChan := make(chan *net.UDPAddr, max(len(remainingTargets)*2, config.GlobalConfig.NAT.MenuResponseChannelSize))
		m.server.PingResponseMu.Lock()
		for _, target := range remainingTargets {
			m.server.PingResponseChans[target.String()] = responseChan
		}
		m.server.PingResponseMu.Unlock()

		if choixRelais == "" || choixRelais == "default" {
			choixRelais = config.GlobalConfig.NAT.DefaultRelayPeer
		}
		fmt.Printf("--- Tentative NAT traversal via %s... ---\n", choixRelais)
		natPerce := m.sendNatTraversalViaPeer(remainingTargets, choixRelais, responseChan)

		// Cleanup des canaux
		m.server.PingResponseMu.Lock()
		for _, target := range remainingTargets {
			delete(m.server.PingResponseChans, target.String())
		}
		m.server.PingResponseMu.Unlock()

		// Si le NAT est percé, tenter la connexion avec Hello sur les adresses qui ont fonctionné
		if natPerce {
			m.sendDirectConnection(remainingTargets, pName, 1)
		}
	}

	// Vérifier le résultat final
	peerInfo, exists = m.server.Manager.Get(pName)
	if exists {
		fmt.Printf("✅ SUCCÈS : Connecté à %s avec %d adresse(s) !\n", pName, len(peerInfo.Addrs))
	} else {
		fmt.Println("❌ ÉCHEC : Impossible de joindre le peer.")
	}
}

// sendDirectConnection envoie des Hello pour tenter une connexion directe
func (m *InteractiveMenu) sendDirectConnection(addresses []*net.UDPAddr, pName string, maxAttempts int) bool {
	startTime := time.Now()

	for range maxAttempts {
		for _, addr := range addresses {
			transport.SendHello(m.server.Conn, addr, m.server.MyName, m.server.PrivKey)
		}
		time.Sleep(time.Duration(config.GlobalConfig.Network.DirectConnectDelayMs) * time.Millisecond)
	}

	// Vérifier si le peer existe et a été vu récemment
	if peerInfo, exists := m.server.Manager.Get(pName); exists {
		if peerInfo.LastSeen.After(startTime) {
			return true
		}
	}
	return false
}

// sendNatTraversalViaPeer utilise un pair comme relais pour le NAT traversal
func (m *InteractiveMenu) sendNatTraversalViaPeer(targetAddresses []*net.UDPAddr, relayPeerName string, responseChan chan *net.UDPAddr) bool {
	relayPeer, exists := m.server.Manager.Get(relayPeerName)
	if !exists {
		fmt.Printf("⚠️ Peer relais %s non connecté. Vous devez d'abord être connecté avec ce peer.\n", relayPeerName)
		return false
	}
	if !relayPeer.IsRelay {
		fmt.Printf("⚠️ Peer relais %s n'est pas configuré comme relais NAT.\n", relayPeerName)
		return false
	}
	fmt.Printf("ℹ️️ Utilisation de %s comme relais (%d adresse(s))\n", relayPeerName, len(relayPeer.Addrs))

	filteredTargets := m.filterAddressesByProtocol(targetAddresses)
	if len(filteredTargets) == 0 {
		fmt.Println("⚠️ Aucune adresse cible compatible avec nos protocols IP.")
		return false
	}

	targetIPv4, targetIPv6 := utils.SeparateAddressesByProtocol(filteredTargets)
	relayAddrs := make([]*net.UDPAddr, 0, len(relayPeer.Addrs))
	for _, addrInfo := range relayPeer.Addrs {
		relayAddrs = append(relayAddrs, addrInfo.Addr)
	}
	relayIPv4, relayIPv6 := utils.SeparateAddressesByProtocol(relayAddrs)

	var succes6, succes4 bool

	if len(targetIPv6) > 0 && len(relayIPv6) > 0 {
		fmt.Println("ℹ️️ Tentative via IPv6...")
		for _, targetAddr := range targetIPv6 {
			transport.SendNatTraversalRequest(m.server.Conn, relayIPv6[0], targetAddr, m.server.PrivKey)
		}
		if m.pingSpam(targetIPv6, config.GlobalConfig.NAT.PingSpamCount, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv6")
			succes6 = true
		}
	}

	if len(targetIPv4) > 0 && len(relayIPv4) > 0 {
		fmt.Println("ℹ️️ Tentative via IPv4...")
		for _, targetAddr := range targetIPv4 {
			transport.SendNatTraversalRequest(m.server.Conn, relayIPv4[0], targetAddr, m.server.PrivKey)
		}
		if m.pingSpam(targetIPv4, config.GlobalConfig.NAT.PingSpamCount, responseChan) {
			fmt.Println("✅ NAT traversal réussi via IPv4")
			succes4 = true
		}
	}

	if succes4 || succes6 {
		return true
	}
	fmt.Println("❌ Échec du NAT traversal via toutes les adresses.")
	return false
}

// pingSpam envoie plusieurs pings pour percer le NAT avec backoff exponentiel.
// Retourne true dès réception d'un ping du pair ou d'un OK en réponse.
func (m *InteractiveMenu) pingSpam(addresses []*net.UDPAddr, count int, responseChan chan *net.UDPAddr) bool {
	return transport.PingWithBackoff(
		m.server.Conn, addresses, count,
		time.Second,
		time.Duration(config.GlobalConfig.NAT.PingSpamFinalTimeoutMs)*time.Millisecond,
		responseChan,
	)
}

// filterAddressesByProtocol filtre les adresses en fonction des protocoles IP locaux
func (m *InteractiveMenu) filterAddressesByProtocol(addresses []*net.UDPAddr) []*net.UDPAddr {
	if !m.hasIPv4 && !m.hasIPv6 {
		fmt.Println("⚠️ Aucun protocole IP disponible !")
		return nil
	}

	var filtered []*net.UDPAddr
	for _, addr := range addresses {
		isIPv4 := utils.IsIPv4(addr)
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
