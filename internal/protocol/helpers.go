package protocol

import "main/internal/config"

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

// typeNames associe chaque type de message à son nom lisible
var typeNames = map[uint8]string{
	Ping: "Ping", Ok: "Ok", Error: "Error",
	Hello: "Hello", HelloReply: "HelloReply",
	RootRequest: "RootRequest", RootReply: "RootReply",
	DatumRequest: "DatumRequest", Datum: "Datum", NoDatum: "NoDatum",
	NatTraversalRequest: "NatTraversalRequest", NatTraversalRequest2: "NatTraversalRequest2",
}

// GetTypeName retourne le nom lisible d'un type de message
func GetTypeName(typ uint8) string {
	if name, ok := typeNames[typ]; ok {
		return name
	}
	return "Unknown"
}
