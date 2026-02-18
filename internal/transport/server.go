package transport

import (
	"context"
	"crypto/ecdsa"
	"main/internal/merkle"
	"main/internal/peer"
	"main/internal/protocol"
	"net"
	"sync"
	"time"
)

type Server struct {
	Conn    *net.UDPConn
	PrivKey *ecdsa.PrivateKey
	MyName  string

	// Composants internes
	Manager     *peer.Manager
	MerkleStore *merkle.Store // Fichiers locaux
	Downloads   *merkle.Store // Fichiers distants
	RootHash    [32]byte

	// Events
	DatumDispatcher *DatumDispatcher
	rootHashChan    chan [32]byte // Canal temporaire pour recevoir la réponse "Root"
	rootHashMu      sync.Mutex

	// Canaux pour détecter les réceptions pendant pingSpam (par adresse cible)
	PingResponseChans map[string]chan *net.UDPAddr
	PingResponseMu    sync.Mutex

	// Sécurité : suivi des requêtes en attente (anti-injection)
	// Hash → set d'adresses de peers à qui on a demandé ce datum
	PendingDatumRequests map[[32]byte]map[string]struct{}
	PendingDatumMu       sync.RWMutex
	PendingRootRequests  map[string]struct{} // Adresses à qui on a envoyé un RootRequest
	PendingRootRequestMu sync.Mutex

	// Cache HTTP pour éviter de spammer l'annuaire
	keyCache   map[string][]byte
	keyCacheMu sync.RWMutex

	workerSem chan struct{}
	workerWg  sync.WaitGroup

	shutdown chan struct{}
}

func NewServer(conn *net.UDPConn, key *ecdsa.PrivateKey, name string) *Server {
	return &Server{
		Conn:                 conn,
		PrivKey:              key,
		MyName:               name,
		Manager:              peer.NewManager(),
		MerkleStore:          merkle.NewStore(),
		Downloads:            merkle.NewStore(),
		DatumDispatcher:      NewDatumDispatcher(),
		keyCache:             make(map[string][]byte),
		PingResponseChans:    make(map[string]chan *net.UDPAddr),
		PendingDatumRequests: make(map[[32]byte]map[string]struct{}),
		PendingRootRequests:  make(map[string]struct{}),
		workerSem:            make(chan struct{}, 100), // Limite à 100 workers concurrents
		shutdown:             make(chan struct{}),
	}
}

// ListenLoop : Boucle principale
func (s *Server) ListenLoop(ctx context.Context) {
	buf := make([]byte, 65535) // max buffer

	for {
		n, remote, err := s.Conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Validation rapide du header AVANT copie (optimisation)
		if n < protocol.HeaderSize {
			continue // Paquet trop court, on ignore
		}

		// Copie nécessaire car buf est écrasé à la prochaine itération
		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		select {
		case s.workerSem <- struct{}{}:
			s.workerWg.Add(1)
			go func() {
				defer func() {
					<-s.workerSem // Libérer le semaphore
					s.workerWg.Done()
				}()
				s.handlePacket(remote, packetData)
			}()
		case <-time.After(100 * time.Millisecond):
			// Trop de workers, on drop le packet
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		}
	}
}

// Stop ferme tout proprement
func (s *Server) Stop() {
	close(s.shutdown)
	s.workerWg.Wait() // Attendre que tous les workers terminent
	s.Conn.Close()
}
