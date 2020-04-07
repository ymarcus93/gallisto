package types

import (
	"crypto/rsa"
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

type LOCType int

const (
	Director LOCType = iota
	Counselor
)

type LOCData struct {
	Type LOCType
	U    []byte
	S    []byte

	// Either c_e or c_a depending on Type. If Director, then c_a. If Counselor,
	// then c_e
	EncryptedKey GCMCiphertext
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
