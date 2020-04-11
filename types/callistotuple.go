package types

import (
	"fmt"

	"github.com/ymarcus93/gallisto/internal/encryption"
)

// CallistoTuple represents the 6-tuple record sent by Callisto clients and
// received by Callisto servers
type CallistoTuple struct {
	userId                            []byte
	pi                                []byte
	locCiphertext                     []byte                   // c
	dlocCiphertext                    []byte                   // c_assign
	encryptedEntryDataKeyUnderUserKey encryption.GCMCiphertext // c_U
	encryptedEntryData                encryption.GCMCiphertext // e_entry
	encryptedAssignmentData           encryption.GCMCiphertext // e_assign
}

// NewCallistoTuple constructs a valid CallistoTuple. Returns a non-nil error if
// provided input is invalid.
func NewCallistoTuple(
	userId, pi, locCiphertext, dlocCiphertext []byte,
	encryptedEntryDataKeyUnderUserKey, encryptedEntryData, encryptedAssignmentData encryption.GCMCiphertext) (CallistoTuple, error) {
	// Validate inputs
	if userId == nil {
		return CallistoTuple{}, fmt.Errorf("userId cannot be nil")
	}
	if pi == nil {
		return CallistoTuple{}, fmt.Errorf("pi cannot be nil")
	}
	if locCiphertext == nil {
		return CallistoTuple{}, fmt.Errorf("locCiphertext cannot be nil")
	}
	if dlocCiphertext == nil {
		return CallistoTuple{}, fmt.Errorf("dlocCiphertext cannot be nil")
	}
	if err := encryptedEntryDataKeyUnderUserKey.IsValid(); err != nil {
		return CallistoTuple{}, fmt.Errorf("encryptedEntryDataKeyUnderUserKey is invalid: %v", err)
	}
	if err := encryptedEntryData.IsValid(); err != nil {
		return CallistoTuple{}, fmt.Errorf("encryptedEntryData is invalid: %v", err)
	}
	if err := encryptedAssignmentData.IsValid(); err != nil {
		return CallistoTuple{}, fmt.Errorf("encryptedAssignmentData is invalid: %v", err)
	}

	return CallistoTuple{
		userId:                            userId,
		pi:                                pi,
		locCiphertext:                     locCiphertext,
		dlocCiphertext:                    dlocCiphertext,
		encryptedEntryDataKeyUnderUserKey: encryptedEntryDataKeyUnderUserKey,
		encryptedEntryData:                encryptedEntryData,
		encryptedAssignmentData:           encryptedAssignmentData,
	}, nil
}

// Getters

// UserID returns the userID of this tuple's submitter
func (c CallistoTuple) UserID() []byte { return c.userId }

// Pi returns the pi value derived from P-Hat. Enables a Callisto server to find
// perpetrator matches between clients.
func (c CallistoTuple) Pi() []byte { return c.pi }

// LOCCiphertext returns the ciphertext to be decrypted by a LOC
func (c CallistoTuple) LOCCiphertext() []byte { return c.locCiphertext }

// DLOCCiphertext returns the ciphertext to be decrypted by a DLOC
func (c CallistoTuple) DLOCCiphertext() []byte { return c.dlocCiphertext }

// EncryptedEntryDataKeyUnderUserKey returns the ciphertext protecting the
// random entry data key created for encrypting entry data. It can only be
// decrypted with the user's key.
func (c CallistoTuple) EncryptedEntryDataKeyUnderUserKey() encryption.GCMCiphertext {
	return c.encryptedEntryDataKeyUnderUserKey
}

// EncryptedEntryData returns the encrypted entry data under k_e
func (c CallistoTuple) EncryptedEntryData() encryption.GCMCiphertext { return c.encryptedEntryData }

// EncryptedAssignmentData returns the encrypted assignment data under k_a
func (c CallistoTuple) EncryptedAssignmentData() encryption.GCMCiphertext {
	return c.encryptedAssignmentData
}
