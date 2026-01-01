package protocol

const (
	Ping = 0
	Ok   = 128

	Error = 129

	Hello      = 1
	HelloReply = 130

	Timeout = 3

	RootRequest = 2
	RootReply   = 131

	DatumRequest = 3
	Datum        = 132
	NoDatum      = 133

	NatTraversalRequest  = 4
	NatTraversalRequest2 = 5

	URL = "https://jch.irif.fr:8443/peers/"

	// Adresses du serveur - on essaie IPv6 d'abord, puis IPv4
	ServerUDPv6 = "[2001:660:3301:9243::51c2:1ee5]:8443"
	ServerUDPv4 = "81.194.30.229:8443"

	MyName   = "heee1"
	FILENAME = "client_key.pem"
)
