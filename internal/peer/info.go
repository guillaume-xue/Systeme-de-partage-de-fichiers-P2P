package peer

import (
	"crypto/ecdsa"
	"net"
	"time"
)

// AddrInfo contient une adresse et son timestamp
type AddrInfo struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
}

// PeerInfo contient les informations sur un peer
type PeerInfo struct {
	Name      string
	Addrs     []AddrInfo // Support IPv4 et IPv6 avec timestamps
	PublicKey *ecdsa.PublicKey
	LastSeen  time.Time
	IsRelay   bool
}

// GetAddr retourne la première adresse (en général la seule) du pair
func (p *PeerInfo) GetAddr() *net.UDPAddr {
	if len(p.Addrs) > 0 {
		return p.Addrs[0].Addr
	}
	return nil
}
