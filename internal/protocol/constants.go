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
)
