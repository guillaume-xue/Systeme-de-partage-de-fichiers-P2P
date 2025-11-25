package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
)

// GeneratePrivateKey crée une nouvelle clé privée ECDSA.
func GeneratePrivateKey() *ecdsa.PrivateKey {
	rprivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Erreur lors de la génération de la clé privée")
	}
	return rprivateKey
}

// ExtractPublicKey extrait la clé publique à partir de la clé privée.
func ExtractPublicKey(privateKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Erreur lors de l'extraction de la clé publique")
	}
	return publicKey
}

// PublicKeyToBytes convertit une clé publique ECDSA en un tableau d'octets.
func PublicKeyToBytes(pub *ecdsa.PublicKey) []byte {
	formatted := make([]byte, 64)
	pub.X.FillBytes(formatted[:32])
	pub.Y.FillBytes(formatted[32:])
	return formatted
}

// ParsePublicKey analyse un tableau d'octets pour créer une clé publique.
func ParsePublicKey(data []byte) *ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(data[:32])
	y.SetBytes(data[32:])
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	return &publicKey
}

// ComputeSignature génère une signature ECDSA pour les données fournies.
func ComputeSignature(privateKey *ecdsa.PrivateKey, data []byte) []byte {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		log.Fatal("Erreur lors de la signature des données")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

// VerifySignature vérifie une signature ECDSA pour les données fournies.
func VerifySignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	ok := ecdsa.Verify(publicKey, hashed[:], &r, &s)
	return ok
}
