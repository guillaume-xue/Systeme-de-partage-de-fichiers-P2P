package protocol

// Types de messages UDP
const (
	Ping = 0
	Ok   = 128

	Error = 129

	Hello      = 1
	HelloReply = 130

	RootRequest = 2
	RootReply   = 131

	DatumRequest = 3
	Datum        = 132
	NoDatum      = 133

	NatTraversalRequest  = 4
	NatTraversalRequest2 = 5

	// Bit 0 : je suis un relais NAT
	ExtNatTraversalRelay = 1
)

const (
	MaxQueueSize = 1024
)

var (
	Debug_Enable = false
)
