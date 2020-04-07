package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/ymarcus93/gallisto/types"
	"github.com/ymarcus93/gallisto/util"
)

// EncryptAES encrypts the given plaintext using the provided key
func EncryptAES(key, plaintext, associatedData []byte) (types.GCMCiphertext, error) {
	aesGCM, err := initAESGCM(key)
	if err != nil {
		return types.GCMCiphertext{}, err
	}

	// AES GCM uses nonces of 12 bytes
	nonce, err := util.GenerateRandomBytes(12)
	if err != nil {
		return types.GCMCiphertext{}, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, associatedData)
	return types.GCMCiphertext{Nonce: nonce, Ciphertext: ciphertext, AssociatedData: associatedData}, nil
}

// DecryptAES decrypts a types.GCMCiphertext using the provided key
func DecryptAES(key []byte, gcmCiphertext types.GCMCiphertext) ([]byte, error) {
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
