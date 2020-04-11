package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ff "github.com/superarius/shamir/modular"

	"github.com/ymarcus93/gallisto/internal/encryption"
	"github.com/ymarcus93/gallisto/internal/shamir"
	helper "github.com/ymarcus93/gallisto/internal/test"
)

func createShamirShare(t *testing.T) *shamir.ShamirShare {
	x := helper.GenerateRandomModularInt(t)
	y := helper.GenerateRandomModularInt(t)
	return &shamir.ShamirShare{X: x, Y: y}
}

func TestNewLOCData_Invalid(t *testing.T) {
	invalidCtxs := helper.CreateInvalidGCMCiphertexts(t)
	tests := map[string]struct {
		locType      LOCType
		shamirShare  *shamir.ShamirShare
		encryptedKey encryption.GCMCiphertext
	}{
		"invalid locType (default)": {
			locType:      0,
			shamirShare:  createShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid locType (out of bounds)": {
			locType:      3,
			shamirShare:  createShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid x point on shamir share": {
			locType:      Director,
			shamirShare:  &shamir.ShamirShare{X: nil, Y: helper.GenerateRandomModularInt(t)},
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid y point on shamir share": {
			locType:      Director,
			shamirShare:  &shamir.ShamirShare{X: helper.GenerateRandomModularInt(t), Y: nil},
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext (nil nonce)": {
			locType:      Director,
			shamirShare:  createShamirShare(t),
			encryptedKey: invalidCtxs[0],
		},
		"invalid ciphertext (nil ciphertext)": {
			locType:      Director,
			shamirShare:  createShamirShare(t),
			encryptedKey: invalidCtxs[1],
		},
		"invalid ciphertext (nil associated data)": {
			locType:      Director,
			shamirShare:  createShamirShare(t),
			encryptedKey: invalidCtxs[2],
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			_, err := NewLOCData(test.locType, test.shamirShare, test.encryptedKey)
			assert.Error(t, err)
		})
	}
}

func TestNewLOCData_Valid(t *testing.T) {
	tests := map[string]struct {
		locType      LOCType
		shamirShare  *shamir.ShamirShare
		encryptedKey encryption.GCMCiphertext
	}{
		"valid director input": {
			locType:      Director,
			shamirShare:  createShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"valid counselor input": {
			locType:      Counselor,
			shamirShare:  createShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			actual, err := NewLOCData(test.locType, test.shamirShare, test.encryptedKey)
			if assert.NoError(t, err) {
				assert.Equal(t, test.locType, actual.locType)
				assert.Equal(t, test.shamirShare.X.Bytes(), actual.u)
				assert.Equal(t, test.shamirShare.Y.Bytes(), actual.s)
				assert.Equal(t, test.encryptedKey, actual.encryptedKey)
			}
		})
	}
}

func TestGetShamirShare(t *testing.T) {
	shamirShare := createShamirShare(t)
	locData, err := NewLOCData(Director, shamirShare, helper.CreateGCMCiphertext(t))
	if err != nil {
		t.Error(err)
	}
	actual := locData.GetShamirShare()
	expected := &shamir.ShamirShare{X: ff.IntFromBytes(shamirShare.X.Bytes()), Y: ff.IntFromBytes(shamirShare.Y.Bytes())}
	assert.Equal(t, expected, actual)
}

func TestMessagePackEncoding(t *testing.T) {
	locData, err := NewLOCData(Director, createShamirShare(t), helper.CreateGCMCiphertext(t))
	if err != nil {
		t.Error(err)
	}
	serialized := locData.ToLOCDataMsgPack()
	deserialized, err := FromLOCDataMsgPack(serialized)
	if err != nil {
		t.Errorf("failed to deserialize msgpack into loc data: %v", err)
	}
	assert.Equal(t, locData, deserialized)
}
