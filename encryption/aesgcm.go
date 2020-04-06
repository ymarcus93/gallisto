package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/vmihailenco/msgpack"
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

func EncryptEntryData(data types.EntryData, pi []byte) (types.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of entry data
	entryDataEncodedBytes, err := msgpack.Marshal(&data)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encode entry data: %v", err)
	}

	// Generate random entry data key: k_e
	entryDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Encrypt entryData to get eEntry
	encryptedEntryData, err := EncryptAES(entryDataKey, entryDataEncodedBytes, pi)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt entry data: %v", err)
	}

	return encryptedEntryData, entryDataKey, nil
}

func EncryptAssignmentData(data types.AssignmentData, pi []byte) (types.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of assignment data
	assignmentDataEncodedBytes, err := msgpack.Marshal(&data)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encode assignment data: %v", err)
	}

	// Generate random assignment data key: k_a
	assignmentDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Encrypt assignmentData to get eAssign
	encryptedAssignmentData, err := EncryptAES(assignmentDataKey, assignmentDataEncodedBytes, pi)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt assignment data: %v", err)
	}

	return encryptedAssignmentData, assignmentDataKey, nil
}

func DecryptEntryData(encryptedEntryData types.GCMCiphertext, entryDataKey []byte) (types.EntryData, error) {
	// Decrypt entry data
	entryDataEncodedBytes, err := DecryptAES(entryDataKey, encryptedEntryData)
	if err != nil {
		return types.EntryData{}, fmt.Errorf("failed to decrypt entry data: %v", err)
	}

	// Decode msgpack encoding
	var decodedEntryData types.EntryData
	err = msgpack.Unmarshal(entryDataEncodedBytes, &decodedEntryData)
	if err != nil {
		return types.EntryData{}, fmt.Errorf("failed to decode entry data: %v", err)
	}

	return decodedEntryData, nil
}

func DecryptAssignmentData(encryptedAssignmentData types.GCMCiphertext, assignmentDataKey []byte) (types.AssignmentData, error) {
	// Decrypt assignment data
	assignmentDataEncodedBytes, err := DecryptAES(assignmentDataKey, encryptedAssignmentData)
	if err != nil {
		return types.AssignmentData{}, fmt.Errorf("failed to decrypt assignment data: %v", err)
	}

	// Decode msgpack encoding
	var decodedAssignmentData types.AssignmentData
	err = msgpack.Unmarshal(assignmentDataEncodedBytes, &decodedAssignmentData)
	if err != nil {
		return types.AssignmentData{}, fmt.Errorf("failed to decode assignment data: %v", err)
	}

	return decodedAssignmentData, nil
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
