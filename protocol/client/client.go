package client

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ymarcus93/gallisto/encoding"
	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/shamir"
	"github.com/ymarcus93/gallisto/types"
	"github.com/ymarcus93/gallisto/util"

	ss "github.com/superarius/shamir"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

type CallistoClient struct {
	UserID       []byte
	userKey      []byte
	pHatComputer PHatComputer
}

// LOCPublicKeys encapsulates the public keys needed by a CallistoClient to
// create ciphertexts for the LOCs
type LOCPublicKeys struct {
	LOCPublicKey  *rsa.PublicKey
	DLOCPublicKey *rsa.PublicKey
}

// CallistoEntry encapsulates all the information a CallistoClient encrypts
type CallistoEntry struct {
	EntryData      types.EntryData
	AssignmentData types.AssignmentData
}

// PHatComputer can transform a low-entropy perpetrator ID into a pseudorandom
// value with sufficient entropy
type PHatComputer interface {
	GetPHatValue(perpID []byte) ([]byte, error)
}

type akpi struct {
	a  []byte
	k  []byte
	pi []byte
}

// NewCallistoClient returns a CallistoClient capabale of performing Callisto
// client responsibilities
func NewCallistoClient(pHatComputer PHatComputer) (*CallistoClient, error) {
	userKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user key: %v", err)
	}

	uuid := uuid.New()
	uuidAsBytes, err := uuid.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal uuid to bytes: %v", err)
	}

	return &CallistoClient{
		userKey:      userKey,
		UserID:       uuidAsBytes,
		pHatComputer: pHatComputer,
	}, nil
}

// CreateCallistoTuple performs the entire Callisto client encryption of a
// Callisto entry and returns the 6-tuple to be sent to a Callisto database
// server
func (c *CallistoClient) CreateCallistoTuple(perpID []byte, entry CallistoEntry, pubKeys LOCPublicKeys) (types.CallistoTuple, error) {
	pHat, err := c.pHatComputer.GetPHatValue(perpID)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to derive p-hat: %v", err)
	}

	// Derive from P-Hat three 32-byte pseudorandom values
	akpiValues, err := deriveAKPiValues(pHat)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to derived a, k, and pi: %v", err)
	}

	// Evaluate shamir polynomial y = ax + k at x = U to get y = s
	shamirShare := shamir.ComputeShamirShare(akpiValues.a, akpiValues.k, c.UserID)

	// Encrypt Callisto entry data
	encryptedCallistoEntryData, err := c.encryptEntry(entry, akpiValues)
	if err != nil {
		return types.CallistoTuple{}, err
	}

	// Encrypt data for LOCs
	locCiphertext, err := encryptLOCData(
		types.Counselor,
		shamirShare,
		encryptedCallistoEntryData.encryptedEntryDataKeyByK,
		pubKeys.LOCPublicKey,
	)
	dlocCiphertext, err := encryptLOCData(
		types.Director,
		shamirShare,
		encryptedCallistoEntryData.encryptedAssignmentDataKeyByK,
		pubKeys.DLOCPublicKey,
	)

	tuple, err := types.NewCallistoTuple(
		akpiValues.pi,
		locCiphertext,
		dlocCiphertext,
		encryptedCallistoEntryData.encryptedEntryDataKeyByU,
		encryptedCallistoEntryData.encryptedEntryData,
		encryptedCallistoEntryData.encryptedAssignmentData,
	)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to construct tuple: %v", err)
	}
	return tuple, nil
}

type encryptedCallistoEntry struct {
	encryptedEntryData       encryption.GCMCiphertext // eEntry value
	encryptedEntryDataKeyByK encryption.GCMCiphertext // c_e value
	encryptedEntryDataKeyByU encryption.GCMCiphertext // c_u value

	encryptedAssignmentData       encryption.GCMCiphertext // eAssign value
	encryptedAssignmentDataKeyByK encryption.GCMCiphertext // c_a value
}

// encryptEntry performs client-side symmetric encryption operations involved in
// encrypting an entry
func (c *CallistoClient) encryptEntry(entry CallistoEntry, akpiValues akpi) (encryptedCallistoEntry, error) {
	// Encrypt entry data: eEntry
	encryptedEntryData, entryDataKey, err := encryptEntryData(entry.EntryData, akpiValues.pi)
	if err != nil {
		return encryptedCallistoEntry{}, fmt.Errorf("failed to encrypt entry data: %v", err)
	}

	// c_e
	encryptedEntryDataKeyByK, err := encryption.EncryptAES(akpiValues.k, entryDataKey, akpiValues.pi)
	if err != nil {
		return encryptedCallistoEntry{}, fmt.Errorf("failed to create c_e: %v", err)
	}

	// c_u
	encryptedEntryDataKeyByU, err := encryption.EncryptAES(c.userKey, entryDataKey, akpiValues.pi)
	if err != nil {
		return encryptedCallistoEntry{}, fmt.Errorf("failed to create c_u: %v", err)
	}

	// Encrypt assignment data: eAssign
	encryptedAssignmentData, assignmentDataKey, err := encryptAssignmentData(entry.AssignmentData, akpiValues.pi)
	if err != nil {
		return encryptedCallistoEntry{}, fmt.Errorf("failed to encrypt assignment data: %v", err)
	}

	// c_a
	encryptedAssignmentDataKey, err := encryption.EncryptAES(akpiValues.k, assignmentDataKey, akpiValues.pi)
	if err != nil {
		return encryptedCallistoEntry{}, fmt.Errorf("failed to create c_a: %v", err)
	}

	return encryptedCallistoEntry{
		encryptedEntryData:            encryptedEntryData,
		encryptedEntryDataKeyByK:      encryptedEntryDataKeyByK,
		encryptedEntryDataKeyByU:      encryptedEntryDataKeyByU,
		encryptedAssignmentData:       encryptedAssignmentData,
		encryptedAssignmentDataKeyByK: encryptedAssignmentDataKey,
	}, nil
}

// encryptEntryData generates a fresh random key and uses it to encrypt
// entry data. The returned result is both the encrypted entry data
// and the random key generated.
func encryptEntryData(data types.EntryData, pi []byte) (encryption.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of entry data
	entryDataEncodedBytes, err := encoding.EncodeEntryData(data)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, err
	}

	// Generate random entry data key: k_e
	entryDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, err
	}

	// Encrypt entryData to get eEntry
	encryptedEntryData, err := encryption.EncryptAES(entryDataKey, entryDataEncodedBytes, pi)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt entry data: %v", err)
	}

	return encryptedEntryData, entryDataKey, nil
}

// encryptAssignmentData generates a fresh random key and uses it to encrypt
// assignment data. The returned result is both the encrypted assignment data
// and the random key generated.
func encryptAssignmentData(data types.AssignmentData, pi []byte) (encryption.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of assignment data
	assignmentDataEncodedBytes, err := encoding.EncodeAssignmentData(data)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, err
	}

	// Generate random assignment data key: k_a
	assignmentDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, err
	}

	// Encrypt assignmentData to get eAssign
	encryptedAssignmentData, err := encryption.EncryptAES(assignmentDataKey, assignmentDataEncodedBytes, pi)
	if err != nil {
		return encryption.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt assignment data: %v", err)
	}

	return encryptedAssignmentData, assignmentDataKey, nil
}

// encryptLOCData forms the c or c_assign tuple (depending on locType) and
// encrypts the necessary data for a LOC
func encryptLOCData(locType types.LOCType, shamirShare *ss.Share, encryptedKey encryption.GCMCiphertext, locPublicKey *rsa.PublicKey) ([]byte, error) {
	locData, err := types.NewLOCData(locType, shamirShare, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to construct loc data: %v", err)
	}

	// Create msgpack encoding of LOC data
	locDataEncodedBytes, err := encoding.EncodeLOCData(locData)
	if err != nil {
		return nil, err
	}

	// Encrypt data to LOC
	locCiphertext, err := encryption.EncryptRSA(locDataEncodedBytes, locPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt locData to %v LOC: %v", locType, err)
	}

	return locCiphertext, nil
}

// deriveAKPiValues derives the triple: (a, k, pi) from a result given by an
// evaluated OPRF function
func deriveAKPiValues(pHat []byte) (akpi, error) {
	// Underlying hash function for HMAC.
	hash := sha256.New
	hkdf := hkdf.New(hash, pHat, nil, nil)

	// Generate three 256-bit derived keys.
	var keys [][]byte
	for i := 0; i < 3; i++ {
		key := make([]byte, 32)
		if _, err := io.ReadFull(hkdf, key); err != nil {
			return akpi{}, fmt.Errorf("failed to derive AKPi values at index %v: %v", i, err)
		}
		keys = append(keys, key)
	}

	return akpi{
		a:  keys[0],
		k:  keys[1],
		pi: keys[2],
	}, nil
}
