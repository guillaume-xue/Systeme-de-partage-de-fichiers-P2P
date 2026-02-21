package transport

import (
	"main/internal/utils"
	"net"
	"time"
)

// PingWithBackoff envoie des pings avec backoff exponentiel vers les adresses cibles.
// Retourne true dès qu'une réponse est détectée via responseChan.
// initialDelay est le délai d'attente après le premier ping (les suivants doublent : 2^i secondes).
// finalTimeout est le délai d'attente total après le dernier envoi.
func PingWithBackoff(conn *net.UDPConn, targets []*net.UDPAddr, count int, initialDelay time.Duration, finalTimeout time.Duration, responseChan chan *net.UDPAddr) bool {
	targetSet := make(map[string]bool)
	for _, addr := range targets {
		targetSet[addr.String()] = true
	}

	totalTimeout := utils.CalExpo2Time(count)

	pierced := make(chan bool, 1)
	go func() {
		timeout := time.After(totalTimeout)
		for {
			select {
			case receivedAddr := <-responseChan:
				if targetSet[receivedAddr.String()] {
					pierced <- true
					return
				}
			case <-timeout:
				pierced <- false
				return
			}
		}
	}()

	for i := range count {
		for _, addr := range targets {
			SendPing(conn, addr)
		}

		select {
		case result := <-pierced:
			return result
		default:
		}

		if i < count-1 {
			waitTime := initialDelay
			if i > 0 {
				waitTime = time.Duration(1<<uint(i)) * time.Second
			}

			select {
			case result := <-pierced:
				return result
			case <-time.After(waitTime):
			}
		}
	}

	select {
	case result := <-pierced:
		return result
	case <-time.After(finalTimeout):
		return false
	}
}
