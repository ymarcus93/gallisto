package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ymarcus93/gallisto/encryption"
	helper "github.com/ymarcus93/gallisto/test"
)

func TestNewCallistoTuple_Invalid(t *testing.T) {
	invalidCtxs := helper.CreateInvalidGCMCiphertexts(t)
	tests := map[string]struct {
		pi, locCiphertext, dlocCiphertext                                              []byte
		encryptedEntryDataKeyUnderUserKey, encryptedEntryData, encryptedAssignmentData encryption.GCMCiphertext
	}{
		"invalid pi (nil)": {
			pi:                                nil,
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid locCiphertext (nil)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     nil,
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid dlocCiphertext (nil)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    nil,
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryDataKeyUnderUserKey (nil nonce)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: invalidCtxs[0],
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryDataKeyUnderUserKey (nil ciphertext)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: invalidCtxs[1],
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryDataKeyUnderUserKey (nil associated data)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: invalidCtxs[2],
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryData (nil nonce)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                invalidCtxs[0],
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryData (nil ciphertext)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                invalidCtxs[1],
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedEntryData (nil associated data)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                invalidCtxs[2],
			encryptedAssignmentData:           helper.CreateGCMCiphertext(t),
		},
		"invalid ciphertext: encryptedAssignmentData (nil nonce)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           invalidCtxs[0],
		},
		"invalid ciphertext: encryptedAssignmentData (nil ciphertext)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           invalidCtxs[1],
		},
		"invalid ciphertext: encryptedAssignmentData (nil associated data)": {
			pi:                                helper.GenerateRandomBytes(32, t),
			locCiphertext:                     helper.GenerateRandomBytes(32, t),
			dlocCiphertext:                    helper.GenerateRandomBytes(32, t),
			encryptedEntryDataKeyUnderUserKey: helper.CreateGCMCiphertext(t),
			encryptedEntryData:                helper.CreateGCMCiphertext(t),
			encryptedAssignmentData:           invalidCtxs[2],
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			_, err := NewCallistoTuple(
				test.pi,
				test.locCiphertext,
				test.dlocCiphertext,
				test.encryptedEntryDataKeyUnderUserKey,
				test.encryptedEntryData,
				test.encryptedAssignmentData)
			assert.Error(t, err)
		})
	}
}

func TestNewCallistoTuple_Valid(t *testing.T) {
	pi := helper.GenerateRandomBytes(32, t)
	locCiphertext := helper.GenerateRandomBytes(32, t)
	dlocCiphertext := helper.GenerateRandomBytes(32, t)
	encryptedEntryDataKeyUnderUserKey := helper.CreateGCMCiphertext(t)
	encryptedEntryData := helper.CreateGCMCiphertext(t)
	encryptedAssignmentData := helper.CreateGCMCiphertext(t)
	actual, err := NewCallistoTuple(pi, locCiphertext, dlocCiphertext, encryptedEntryDataKeyUnderUserKey, encryptedEntryData, encryptedAssignmentData)
	if assert.NoError(t, err) {
		assert.Equal(t, pi, actual.pi)
		assert.Equal(t, locCiphertext, actual.locCiphertext)
		assert.Equal(t, dlocCiphertext, actual.dlocCiphertext)
		assert.Equal(t, encryptedEntryDataKeyUnderUserKey, actual.encryptedEntryDataKeyUnderUserKey)
		assert.Equal(t, encryptedEntryData, actual.encryptedEntryData)
		assert.Equal(t, encryptedAssignmentData, actual.encryptedAssignmentData)
	}
}
