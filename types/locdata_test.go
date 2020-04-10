package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/superarius/shamir"
	ff "github.com/superarius/shamir/modular"

	"github.com/ymarcus93/gallisto/encryption"
	helper "github.com/ymarcus93/gallisto/test"
)

func TestNewLOCData_Invalid(t *testing.T) {
	invalidCtxs := helper.CreateInvalidGCMCiphertexts(t)
	tests := map[string]struct {
		locType      LOCType
		shamirShare  *shamir.Share
		encryptedKey encryption.GCMCiphertext
	}{
		"invalid locType (default)": {
			locType:      0,
			shamirShare:  helper.CreateShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid locType (out of bounds)": {
			locType:      3,
			shamirShare:  helper.CreateShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid x point on shamir share": {
			locType:      Director,
			shamirShare:  &shamir.Share{X: nil, Y: helper.GenerateRandomModularInt(t)},
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid y point on shamir share": {
			locType:      Director,
			shamirShare:  &shamir.Share{X: helper.GenerateRandomModularInt(t), Y: nil},
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext (nil nonce)": {
			locType:      Director,
			shamirShare:  helper.CreateShamirShare(t),
			encryptedKey: invalidCtxs[0],
		},
		"invalid ciphertext (nil ciphertext)": {
			locType:      Director,
			shamirShare:  helper.CreateShamirShare(t),
			encryptedKey: invalidCtxs[1],
		},
		"invalid ciphertext (nil associated data)": {
			locType:      Director,
			shamirShare:  helper.CreateShamirShare(t),
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
		shamirShare  *shamir.Share
		encryptedKey encryption.GCMCiphertext
	}{
		"valid director input": {
			locType:      Director,
			shamirShare:  helper.CreateShamirShare(t),
			encryptedKey: helper.CreateGCMCiphertext(t),
		},
		"valid counselor input": {
			locType:      Counselor,
			shamirShare:  helper.CreateShamirShare(t),
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
	shamirShare := helper.CreateShamirShare(t)
	locData, err := NewLOCData(Director, shamirShare, helper.CreateGCMCiphertext(t))
	if err != nil {
		t.Error(err)
	}
	actual := locData.GetShamirShare()
	expected := &shamir.Share{X: ff.IntFromBytes(shamirShare.X.Bytes()), Y: ff.IntFromBytes(shamirShare.Y.Bytes())}
	assert.Equal(t, expected, actual)
}

func TestMessagePackEncoding(t *testing.T) {
	locData, err := NewLOCData(Director, helper.CreateShamirShare(t), helper.CreateGCMCiphertext(t))
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
