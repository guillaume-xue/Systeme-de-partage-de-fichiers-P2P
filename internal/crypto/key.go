package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
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

func LoadOrGenerateKey(filename string) (*ecdsa.PrivateKey, error) {
	fileData, err := os.ReadFile(filename)

	if err == nil {
		block, _ := pem.Decode(fileData)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("format de clé invalide dans %s", filename)
		}
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return privateKey, nil
	}

	if os.IsNotExist(err) {
		privateKey := GeneratePrivateKey()
		keyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		pemBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}

		err = os.WriteFile(filename, pem.EncodeToMemory(pemBlock), 0600)
		if err != nil {
			return nil, err
		}

		fmt.Printf("Nouvelle clé sauvegardée dans '%s'\n", filename)
		return privateKey, nil
	}
	return nil, err
}
