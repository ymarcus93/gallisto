package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

type RSAKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// EncryptRSA encrypts the given message using the provided RSA public key
func EncryptRSA(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, msg, label)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt the message: %v", err)
	}

	return ciphertext, nil
}

// DecryptRSA decrypts the given ciphertext using the provided RSA private key
func DecryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	return plaintext, nil
}

// GenerateRSAKeyPair creates a 4096-bit RSA key
func GenerateRSAKeyPair() (RSAKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return RSAKeyPair{}, fmt.Errorf("failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	return RSAKeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}
