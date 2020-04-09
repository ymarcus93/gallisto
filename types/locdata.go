package types

import (
	"fmt"

	"github.com/ymarcus93/gallisto/encryption"

	"github.com/superarius/shamir"
	ff "github.com/superarius/shamir/modular"
)

// LOCDataMsgPack encapsulates the same information as LOCData but is used for
// MessagePack encoding purposes
type LOCDataMsgPack struct {
	LocType      LOCType
	U            []byte
	S            []byte
	EncryptedKey encryption.GCMCiphertext
}

// LOCData encapsulates the 3-tuple plaintext that is encrypted for LOCs
type LOCData struct {
	locType      LOCType
	u            []byte
	s            []byte
	encryptedKey encryption.GCMCiphertext
}

// NewLOCData constructs a valid LOCData. Returns a non-nil error if provided
// input is invalid.
func NewLOCData(locType LOCType, shamirShare *shamir.Share, encryptedKey encryption.GCMCiphertext) (LOCData, error) {
	if locType == Unknown {
		return LOCData{}, fmt.Errorf("locType cannot be Unknown")
	}
	if shamirShare.X == nil {
		return LOCData{}, fmt.Errorf("shamir share x value cannot be nil")
	}
	if shamirShare.Y == nil {
		return LOCData{}, fmt.Errorf("shamir share y value cannot be nil")
	}
	if err := encryptedKey.IsValid(); err != nil {
		return LOCData{}, fmt.Errorf("encryptedKey is invalid: %v", err)
	}

	return LOCData{
		locType:      locType,
		u:            shamirShare.X.Bytes(),
		s:            shamirShare.Y.Bytes(),
		encryptedKey: encryptedKey,
	}, nil
}

// ToLOCDataMsgPack converts LOCData into a struct that can be MessagePack
// encoded
func (d LOCData) ToLOCDataMsgPack() LOCDataMsgPack {
	return LOCDataMsgPack{
		LocType:      d.locType,
		U:            d.u,
		S:            d.s,
		EncryptedKey: d.encryptedKey,
	}
}

// FromLOCDataMsgPack converts LOCData that is message-pack encoded into a
// LOCData struct
func FromLOCDataMsgPack(msgPackEncodedData LOCDataMsgPack) (LOCData, error) {
	share := getShamirShare(msgPackEncodedData.U, msgPackEncodedData.S)
	return NewLOCData(msgPackEncodedData.LocType, share, msgPackEncodedData.EncryptedKey)
}

// Getters

// LocType returns either Director or Counselor. The result depends on the
// intended recipent of this data
func (d LOCData) LocType() LOCType { return d.locType }

// EncryptedKey returns the encrypted entry or assignment key. If LocType() is
// Director, then the encrypted assignment key is returned. If LocType() is
// Counselor, then the encrypted entry key is returned.
func (d LOCData) EncryptedKey() encryption.GCMCiphertext { return d.encryptedKey }

// GetShamirShare returns the (U, s) shamir share contained within LOCData
func (d LOCData) GetShamirShare() *shamir.Share {
	return getShamirShare(d.u, d.s)
}

func getShamirShare(x, y []byte) *shamir.Share {
	return &shamir.Share{
		X: ff.IntFromBytes(x),
		Y: ff.IntFromBytes(y),
	}
}
