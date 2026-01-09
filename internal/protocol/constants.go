package protocol

import "main/internal/config"

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
)

var (
	Debug_Enable = false
)

// Helpers pour accéder à la config au cas où json a un problème
func GetURL() string {
	if config.GlobalConfig != nil {
		return config.GlobalConfig.Server.URL
	}
	return "https://jch.irif.fr:8443/peers/"
}

func GetServerUDPv4() string {
	if config.GlobalConfig != nil {
		return config.GlobalConfig.Server.IPv4Address
	}
	return "81.194.30.229:8443"
}

func GetServerUDPv6() string {
	if config.GlobalConfig != nil {
		return config.GlobalConfig.Server.IPv6Address
	}
	return "[2001:660:3301:9243::51c2:1ee5]:8443"
}

// GetTypeName retourne le nom lisible d'un type de message
func GetTypeName(typ uint8) string {
	switch typ {
	case Ping:
		return "Ping"
	case Ok:
		return "Ok"
	case Error:
		return "Error"
	case Hello:
		return "Hello"
	case HelloReply:
		return "HelloReply"
	case RootRequest:
		return "RootRequest"
	case RootReply:
		return "RootReply"
	case DatumRequest:
		return "DatumRequest"
	case Datum:
		return "Datum"
	case NoDatum:
		return "NoDatum"
	case NatTraversalRequest:
		return "NatTraversalRequest"
	case NatTraversalRequest2:
		return "NatTraversalRequest2"
	default:
		return "Unknown"
	}
}
