package types

import (
	"crypto/rsa"
	"math/big"
)

const OPRF_CIPHERSUITE string = "OPRF-P521-HKDF-SHA512-SSWU-RO"

// GCMCiphertext holds the three components of an AES-GCM ciphertext
type GCMCiphertext struct {
	Nonce          []byte
	Ciphertext     []byte
	AssociatedData []byte
}

type EntryData struct {
	PerpetratorName            string
	PerpetratorTwitterUserName string
	VictimName                 string
	VictimPhoneNumber          string
	VictimEmail                string
}

type AssignmentData struct {
	VictimStateOfCurrentResidence    string
	CategorizationOfSexualMisconduct string
	IndustryOfPerpetrator            string
}

type LOCData struct {
	U                     *big.Int
	S                     *big.Int
	EncryptedEntryDataKey GCMCiphertext // c_e
}

type DLOCData struct {
	U                          *big.Int
	S                          *big.Int
	EncryptedAssignmentDataKey GCMCiphertext // c_a
}

type CallistoTuple struct {
	Pi                                []byte
	LOCCiphertext                     []byte
	DLOCCiphertext                    []byte
	EncryptedEntryDataKeyUnderUserKey GCMCiphertext
	EncryptedEntryData                GCMCiphertext
	EncryptedAssignmentData           GCMCiphertext
}

type LOCPublicKeys struct {
	LOCPublicKey  *rsa.PublicKey
	DLOCPublicKey *rsa.PublicKey
}

type CallistoEntry struct {
	EntryData      EntryData
	AssignmentData AssignmentData
}
