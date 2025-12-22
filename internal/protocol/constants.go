package protocol

const (
	Ping = 0
	Ok   = 128

	Error = 129

	Hello      = 1
	HelloReply = 130

	Timeout = 5

	RootRequest = 2
	RootReply   = 131

	DatumRequest = 3
	Datum        = 132
	NoDatum      = 133

	NoTraversalRequest  = 4
	NoTraversalRequest2 = 4

	URL       = "https://jch.irif.fr:8443/peers/"
	ServerUDP = "[2001:660:3301:9243::51c2:1ee5]:8443"
	MyName    = "heee1"
	FILENAME  = "client_key.pem"
)
