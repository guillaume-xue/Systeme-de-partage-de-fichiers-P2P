package protocol

type Messages struct {
	ID        uint32
	Type      uint8
	Length    uint16
	Body      uint32
	Signature [32]byte
}

type HelloMessage struct {
	IP         uint32
	Type       uint8
	Length     uint16
	Extensions [32]byte
	Name       uint8
	Signature  uint32
}

type RootDataMessage struct {
	ID     uint32
	Type   uint8
	Length uint16
	Hash   [32]byte
}

type DatumMessage struct {
	ID        uint32
	Type      uint8
	Length    uint16
	Hash      [32]byte
	Value     []byte
	Signature [32]byte
}
