package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/ymarcus93/gallisto/util"
)

// GCMCiphertext holds the three components of an AES-GCM ciphertext
type GCMCiphertext struct {
	Nonce          []byte
	Ciphertext     []byte
	AssociatedData []byte
}

// IsValid validates the GCMCiphertext struct and returns a non-nil error if it
// is invalid. The returned error is nil if the struct is valid.
func (c GCMCiphertext) IsValid() error {
	if c.Nonce == nil {
		return fmt.Errorf("Nonce cannot be nil")
	}
	if c.Ciphertext == nil {
		return fmt.Errorf("Ciphertext cannot be nil")
	}
	if c.AssociatedData == nil {
		return fmt.Errorf("AssociatedData cannot be nil")
	}
	return nil
}

// EncryptAES encrypts the given plaintext using the provided key
func EncryptAES(key, plaintext, associatedData []byte) (GCMCiphertext, error) {
	aesGCM, err := initAESGCM(key)
	if err != nil {
		return GCMCiphertext{}, err
	}

	// AES GCM uses nonces of 12 bytes
	nonce, err := util.GenerateRandomBytes(12)
	if err != nil {
		return GCMCiphertext{}, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, associatedData)
	return GCMCiphertext{Nonce: nonce, Ciphertext: ciphertext, AssociatedData: associatedData}, nil
}

// DecryptAES decrypts a GCMCiphertext using the provided key
func DecryptAES(key []byte, gcmCiphertext GCMCiphertext) ([]byte, error) {
	aesGCM, err := initAESGCM(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, gcmCiphertext.Nonce, gcmCiphertext.Ciphertext, gcmCiphertext.AssociatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	return plaintext, nil
}

func initAESGCM(key []byte) (cipher.AEAD, error) {
	aesBlockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate AES block cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(aesBlockCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate AES-GCM: %v", err)
	}
	return aesGCM, nil
}
