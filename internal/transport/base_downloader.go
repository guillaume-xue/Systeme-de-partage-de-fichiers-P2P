package transport

import (
	"main/internal/config"
	"net"
	"sync"
)

// downloadBase contient les champs et méthodes communes aux Downloader et DiskDownloader.
// Les deux downloaders l'embarquent pour éviter la duplication des champs de lifecycle,
// du tracker, et de la logique de signalisation.
type downloadBase struct {
	server   *Server
	peerAddr *net.UDPAddr
	tracker  *InflightTracker

	responseCh  chan [32]byte
	done        chan struct{}
	running     bool
	wg          sync.WaitGroup
	unsubscribe func()
}

func newDownloadBase(server *Server, peerAddr *net.UDPAddr) downloadBase {
	cfg := config.GlobalConfig.Network
	fc := NewFlowControl(cfg.InitialWindow, cfg.MinWindowSize, cfg.MaxWindowSize, cfg.TimeoutDownload)
	return downloadBase{
		server:     server,
		peerAddr:   peerAddr,
		tracker:    NewInflightTracker(fc, server.Pending, peerAddr),
		responseCh: make(chan [32]byte, cfg.MaxQueueSize),
		done:       make(chan struct{}),
		running:    true,
	}
}

// signalResponse envoie un hash sur le canal de réponse sans bloquer.
// Utilisé par les callbacks onDatumReceived des deux downloaders.
func (b *downloadBase) signalResponse(hash [32]byte) {
	go func() {
		select {
		case b.responseCh <- hash:
		case <-b.done:
		}
	}()
}
