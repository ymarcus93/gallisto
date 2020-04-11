package test

import (
	"testing"

	"github.com/superarius/shamir"
	"github.com/superarius/shamir/modular"
	"github.com/ymarcus93/gallisto/internal/encryption"
	"github.com/ymarcus93/gallisto/internal/util"
)

func GenerateRandomBytes(num int, t *testing.T) []byte {
	randBytes, err := util.GenerateRandomBytes(num)
	if err != nil {
		t.Fatalf("failed to generate %v random bytes: %v", num, err)
	}
	return randBytes
}

func CreateGCMCiphertext(t *testing.T) encryption.GCMCiphertext {
	listOfRandBytes := make([][]byte, 3)
	for i := range listOfRandBytes {
		randBytes, err := util.GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("failed to generate random bytes: %v", err)
		}
		listOfRandBytes[i] = randBytes
	}
	return encryption.GCMCiphertext{
		Nonce:          listOfRandBytes[0],
		Ciphertext:     listOfRandBytes[1],
		AssociatedData: listOfRandBytes[2],
	}
}

func CreateInvalidGCMCiphertexts(t *testing.T) []encryption.GCMCiphertext {
	nilNonce := encryption.GCMCiphertext{Nonce: nil, Ciphertext: GenerateRandomBytes(32, t), AssociatedData: GenerateRandomBytes(32, t)}
	nilCiphertext := encryption.GCMCiphertext{Nonce: GenerateRandomBytes(32, t), Ciphertext: nil, AssociatedData: GenerateRandomBytes(32, t)}
	nilAssociatedData := encryption.GCMCiphertext{Nonce: GenerateRandomBytes(32, t), Ciphertext: GenerateRandomBytes(32, t), AssociatedData: nil}
	return []encryption.GCMCiphertext{nilNonce, nilCiphertext, nilAssociatedData}
}

func GenerateRandomModularInt(t *testing.T) *modular.Int {
	rand, err := modular.RandInt()
	if err != nil {
		t.Fatalf("failed to generate random modular int: %v", err)
	}
	return rand
}

func CreateShamirShare(t *testing.T) *shamir.Share {
	x := GenerateRandomModularInt(t)
	y := GenerateRandomModularInt(t)
	return &shamir.Share{X: x, Y: y}
}
