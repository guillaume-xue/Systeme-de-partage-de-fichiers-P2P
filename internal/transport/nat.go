package transport

import (
	"fmt"
	"main/internal/config"
	"main/internal/crypto"
	"main/internal/protocol"
	"main/internal/utils"
	"net"
	"time"
)

// onNatRequest : un peer nous demande de relayer vers une cible (Logique Relais)
func (s *Server) onNatRequest(pkt *protocol.Packet, srcAddr *net.UDPAddr) {
	// Src demande à contacter Target via nous
	targetStruct, err := protocol.DecodeSocketAddress(pkt.Body)
	if err != nil {
		return
	}

	// On vérifie la signature de Src
	p, ok := s.Manager.GetByAddr(srcAddr)
	if !ok || !crypto.VerifySignature(p.PublicKey, pkt.DataToSign(), pkt.Signature) {
		fmt.Printf("⚠️ NatRequest d'un peer inconnu ou mauvaise signature: %s\n", srcAddr)
		return
	}

	// Vérifier si on connaît la cible (si on est connecté avec elle)
	targetAddr := targetStruct.ToUDPAddr()
	targetPeer, targetKnown := s.Manager.GetByAddr(targetAddr)

	if !targetKnown {
		// La cible n'est pas dans nos pairs connectés, on ne peut pas relayer
		fmt.Printf("⚠️ NAT: %s demande à contacter %s mais cette cible n'est pas connectée à nous\n", srcAddr, targetAddr)
		SendError(s.Conn, srcAddr, "Cible non connecté", pkt.Header.ID)
		return
	}

	// On dit OK à Src
	SendOk(s.Conn, srcAddr, pkt.Header.ID)

	// On envoie une notif à Target à l'adresse demandée
	fmt.Printf("ℹ️️ NAT: %s veut contacter %s (%s) via nous\n", srcAddr, targetPeer.Name, targetAddr)

	// Envoyer NatTraversalRequest2 à l'adresse spécifique demandée par le source
	SendNatTraversalRequest2(s.Conn, targetAddr, srcAddr, s.PrivKey)
}

// onNatRequest2 : le relais nous signale qu'un peer veut nous contacter
func (s *Server) onNatRequest2(pkt *protocol.Packet, relayAddr *net.UDPAddr) {
	// Le Relais nous dit que Src veut nous parler
	srcStruct, err := protocol.DecodeSocketAddress(pkt.Body)
	if err != nil {
		return
	}

	// Vérification de la signature du relais
	relay, ok := s.Manager.GetByAddr(relayAddr)
	if !ok || !crypto.VerifySignature(relay.PublicKey, pkt.DataToSign(), pkt.Signature) {
		fmt.Printf("⚠️ NatRequest2 d'un relais inconnu: %s\n", relayAddr)
		return
	}

	// On dit merci au relais
	SendOk(s.Conn, relayAddr, pkt.Header.ID)

	srcAddr := srcStruct.ToUDPAddr()
	srcAddrKey := srcAddr.String() // Cache une seule fois
	fmt.Printf("ℹ️️ NAT: %s nous demande de pinguer %s\n", relayAddr, srcAddrKey)

	// Créer un canal pour détecter les réceptions de cette adresse
	responseChan := make(chan *net.UDPAddr, config.GlobalConfig.NAT.ResponseChannelSize)
	s.PingResponseMu.Lock()
	s.PingResponseChans[srcAddrKey] = responseChan
	s.PingResponseMu.Unlock()

	defer func() {
		s.PingResponseMu.Lock()
		delete(s.PingResponseChans, srcAddrKey)
		s.PingResponseMu.Unlock()
	}()

	// Calculer le timeout total avec backoff exponentiel
	count := config.GlobalConfig.NAT.PingCount
	totalTimeout := utils.CalExpo2Time(count)

	// Canal pour détecter le succès
	success := make(chan bool, 1)
	stopSending := make(chan bool)

	go func() {
		for {
			select {
			case receivedAddr := <-responseChan:
				if receivedAddr.String() == srcAddrKey {
					close(stopSending) // Signaler l'arrêt
					select {
					case success <- true:
					default:
					}
					return
				}
			case <-time.After(totalTimeout):
				select {
				case success <- false:
				default:
				}
				return
			}
		}
	}()

	// Envoyer des pings avec backoff exponentiel
	for i := range count {
		select {
		case <-stopSending:
			// Succès détecté, on arrête immédiatement
			<-success
			fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
			return
		default:
			SendPing(s.Conn, srcAddr)

			// Attendre avec backoff exponentiel (sauf après le dernier ping)
			if i < count-1 {
				var waitTime time.Duration
				if i == 0 {
					waitTime = time.Duration(config.GlobalConfig.NAT.InitialPingDelaySeconds) * time.Second
				} else {
					waitTime = time.Duration(1<<uint(i)) * time.Second
				}

				// Attendre avec possibilité d'interruption
				select {
				case <-stopSending:
					<-success
					fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
					return
				case <-time.After(waitTime):
					// Continuer à la prochaine itération
				}
			}
		}
	}

	// Attendre le résultat final
	select {
	case result := <-success:
		if result {
			fmt.Printf("✅ NAT traversal réussi avec %s\n", srcAddr)
		} else {
			fmt.Printf("⚠️ Timeout NAT avec %s\n", srcAddr)
		}
	case <-time.After(time.Duration(config.GlobalConfig.NAT.FinalTimeoutMs) * time.Millisecond):
		fmt.Printf("⚠️ Timeout NAT avec %s\n", srcAddr)
	}
}
