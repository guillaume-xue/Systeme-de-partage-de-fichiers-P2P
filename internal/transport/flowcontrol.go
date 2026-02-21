package transport

import (
	"main/internal/config"
	"sync"
	"time"
)

// FlowControl gère le contrôle de congestion et l'estimation RTT (RFC 6298)
// partagé entre Downloader et DiskDownloader.
type FlowControl struct {
	mu sync.Mutex

	// Paramètres de fenêtre
	WindowSize    int
	MaxWindowSize int
	MinWindowSize int
	Timeout       time.Duration // Timeout max (borne supérieure du RTO)

	// RTT estimation (RFC 6298)
	SRTT    time.Duration // Moyenne lissée du RTT
	RTTVar  time.Duration // Variance lissée du RTT
	RTO     time.Duration // Timeout de retransmission dynamique
	rttInit bool          // Premier échantillon reçu ?

	// Contrôle de congestion
	SSThresh int // Seuil slow-start / congestion avoidance
}

// NewFlowControl crée un FlowControl avec les paramètres donnés.
func NewFlowControl(initial, minWin, maxWin int, timeout time.Duration) *FlowControl {
	return &FlowControl{
		WindowSize:    initial,
		MaxWindowSize: maxWin,
		MinWindowSize: minWin,
		Timeout:       timeout,
		RTO:           timeout,
		SSThresh:      maxWin,
	}
}

// UpdateRTT met à jour l'estimation RTT (RFC 6298 §2.2-2.3) et fait grandir la fenêtre.
// Constantes :  α = 1/8 (SRTT), β = 1/4 (RTTVAR), K = 4 (RTO)
func (fc *FlowControl) UpdateRTT(sample time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// 1. Mise à jour RTT
	if !fc.rttInit {
		fc.SRTT = sample
		fc.RTTVar = sample / 2
		fc.rttInit = true
	} else {
		diff := fc.SRTT - sample
		if diff < 0 {
			diff = -diff
		}
		fc.RTTVar = (3*fc.RTTVar + diff) / 4 // β = 1/4
		fc.SRTT = (7*fc.SRTT + sample) / 8   // α = 1/8
	}

	// 2. RTO = SRTT + 4 * RTTVAR (borné [minRTO, timeout])
	minRTO := config.GlobalConfig.Network.MinRTO
	fc.RTO = min(max(fc.SRTT+4*fc.RTTVar, minRTO), fc.Timeout)

	// 3. Fenêtre : grandir si latence ≤ moyenne
	fc.growWindow(sample)
}

// GrowWindowOnly ajuste la fenêtre sans toucher au RTT (Algorithme de Karn : paquet retransmis).
func (fc *FlowControl) GrowWindowOnly(sample time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.rttInit {
		return
	}
	fc.growWindow(sample)
}

// OnTimeout réduit la fenêtre (multiplicative decrease) et double le RTO.
func (fc *FlowControl) OnTimeout() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.SSThresh = max(fc.WindowSize/2, fc.MinWindowSize)
	fc.WindowSize = max(fc.WindowSize/2, fc.MinWindowSize)
	fc.RTO = min(fc.RTO*2, fc.Timeout)
}

// CanSend retourne true si on peut envoyer un nouveau paquet (inflight < window).
func (fc *FlowControl) CanSend(inflight int) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return inflight < fc.WindowSize
}

// Snapshot retourne les métriques courantes (pour l'affichage).
func (fc *FlowControl) Snapshot() (windowSize int, rtt, rto time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.WindowSize, fc.SRTT, fc.RTO
}

// growWindow augmente la fenêtre selon le mode (slow-start ou congestion avoidance).
// Doit être appelée sous le lock.
func (fc *FlowControl) growWindow(sample time.Duration) {
	if sample <= fc.SRTT && fc.WindowSize < fc.MaxWindowSize {
		if fc.WindowSize < fc.SSThresh {
			fc.WindowSize += 2 // Slow Start
		} else {
			fc.WindowSize++ // Congestion Avoidance
		}
		if fc.WindowSize > fc.MaxWindowSize {
			fc.WindowSize = fc.MaxWindowSize
		}
	}
}
