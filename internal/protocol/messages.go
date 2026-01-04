package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"main/internal/crypto"
)

func DecodeHeader(data []byte) (uint32, uint8, uint16, error) {
	if len(data) < 7 {
		return 0, 0, 0, fmt.Errorf("données trop courtes pour un en-tête")
	}

	reader := bytes.NewReader(data[:7])
	var id uint32
	var msgType uint8
	var length uint16

	binary.Read(reader, binary.BigEndian, &id)
	binary.Read(reader, binary.BigEndian, &msgType)
	binary.Read(reader, binary.BigEndian, &length)

	return id, msgType, length, nil
}

func DecodeMessages(data []byte) (uint32, uint8, uint16, []byte, []byte, error) {
	if len(data) < 7 {
		return 0, 0, 0, nil, nil, fmt.Errorf("données trop courtes pour un en-tête")
	}

	id, msgType, length, err := DecodeHeader(data)

	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	var body []byte
	var signature []byte

	if len(data) < 7+int(length) {
		return 0, 0, 0, nil, nil, fmt.Errorf("paquet corrompu (Body incomplet)")
	}

	body = data[7 : 7+length]
	if len(data) >= 7+int(length)+64 {
		signature = data[7+int(length) : 7+int(length)+64]
	}

	fmt.Printf("Parsed Message - ID: %d, Type: %d, Length: %d\n", id, msgType, length)
	fmt.Printf("Body: %v\n", body)
	fmt.Printf("Signature: %v\n\n", signature)

	return id, msgType, length, body, signature, nil
}

func DecodeHandshakeMessage(data []byte) (uint32, uint8, uint16, uint32, []byte, []byte, error) {
	if len(data) < 4 {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("Hello invalide (pas d'extensions)")
	}

	id, msgType, length, err := DecodeHeader(data)

	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}

	var extensions uint32
	var name []byte
	var signature []byte

	binary.Read(bytes.NewReader(data[7:11]), binary.BigEndian, &extensions)

	if len(data) < 11+int(length)-4 {
		return 0, 0, 0, 0, nil, nil, fmt.Errorf("paquet corrompu (Body incomplet)")
	}

	name = data[11 : 11+length-4]

	if len(data) >= 11+int(length)-4+64 {
		signature = data[11+int(length)-4 : 11+int(length)-4+64]
	}

	fmt.Printf("Parsed Message - ID: %d, Type: %d, Length: %d, Extensions: %d\n", id, msgType, length, extensions)
	fmt.Printf("Body: %v\n", name)
	fmt.Printf("Signature: %v\n\n", signature)

	return id, msgType, length, extensions, name, signature, nil
}

func DecodeRootAndData(data []byte) (uint32, uint8, uint16, []byte, error) {
	id, msgType, length, hash, _, err := DecodeMessages(data)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return id, msgType, length, hash, nil
}

func DecodeDatum(data []byte) (uint32, uint8, uint16, []byte, []byte, []byte, error) {
	if len(data) < 4 {
		return 0, 0, 0, nil, nil, nil, fmt.Errorf("Datum invalide (pas d'extensions)")
	}
	id, msgType, length, err := DecodeHeader(data)

	if err != nil {
		return 0, 0, 0, nil, nil, nil, err
	}

	var hash []byte
	var value []byte
	var signature []byte

	if len(data) < 4+int(length) {
		return 0, 0, 0, nil, nil, nil, fmt.Errorf("paquet corrompu (Body incomplet)")
	}

	hash = data[7 : 7+32]

	value = data[7+32 : 7+int(length)]

	if len(data) >= 7+int(length)+64 {
		signature = data[7+int(length) : 7+int(length)+64]
	}

	fmt.Printf("Parsed Datum - ID: %d, Type: %d, Length: %d\n", id, msgType, length)
	fmt.Printf("Hash: %v\n", hash)
	fmt.Printf("Value: %v\n", value)
	fmt.Printf("Signature: %v\n\n", signature)
	return id, msgType, length, hash, value, signature, nil
}

func EncodeHeader(id uint32, msgType uint8, length uint16) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, id)
	binary.Write(buf, binary.BigEndian, msgType)
	binary.Write(buf, binary.BigEndian, length)

	return buf.Bytes()
}

func EncodeMessages(id uint32, msgType uint8, body []byte) []byte {
	length := uint16(len(body))

	headerBytes := EncodeHeader(id, msgType, length)

	date := append(headerBytes, body...)

	privKey, _ := crypto.LoadOrGenerateKey(FILENAME)
	signature := crypto.ComputeSignature(privKey, date)

	message := append(date, signature...)

	return message
}

func EncodeHandshakeMessage(id uint32, msgType uint8, extensions uint32, name []byte) []byte {
	bodyBuf := new(bytes.Buffer)

	binary.Write(bodyBuf, binary.BigEndian, extensions)
	bodyBuf.Write(name)

	body := bodyBuf.Bytes()
	length := uint16(len(body))

	headerBytes := EncodeHeader(id, msgType, length)

	data := append(headerBytes, body...)

	privKey, _ := crypto.LoadOrGenerateKey(FILENAME)
	signature := crypto.ComputeSignature(privKey, data)

	message := append(data, signature...)

	return message
}

func EncodeRootAndData(id uint32, msgType uint8, hash []byte) []byte {
	bodyBuf := new(bytes.Buffer)
	bodyBuf.Write(hash)

	body := bodyBuf.Bytes()
	length := uint16(len(body))

	headerBytes := EncodeHeader(id, msgType, length)

	packetData := append(headerBytes, body...)

	privKey, _ := crypto.LoadOrGenerateKey(FILENAME)
	signature := crypto.ComputeSignature(privKey, packetData)

	message := append(packetData, signature...)

	return message
}
