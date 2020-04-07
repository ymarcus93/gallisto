package callisto

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ymarcus93/gallisto/encoding"
	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/oprf"
	"github.com/ymarcus93/gallisto/shamir"
	"github.com/ymarcus93/gallisto/types"
	"github.com/ymarcus93/gallisto/util"

	ss "github.com/superarius/shamir"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

type CallistoClient struct {
	UserID     []byte
	userKey    []byte
	oprfClient *oprf.OPRFClient
}

type akpi struct {
	a  []byte
	k  []byte
	pi []byte
}

// NewCallistoClient returns a CallistoClient capabale of performing Callisto
// client responsibilities
func NewCallistoClient(ciphersuite string) (*CallistoClient, error) {
	userKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user key: %v", err)
	}

	oprfClient, err := oprf.NewOPRFClient(types.OPRF_CIPHERSUITE)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPRF client: %v", err)
	}

	uuid := uuid.New()
	uuidAsBytes, err := uuid.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal uuid to bytes: %v", err)
	}

	return &CallistoClient{
		userKey:    userKey,
		oprfClient: oprfClient,
		UserID:     uuidAsBytes,
	}, nil
}

// CreateCallistoTuple performs the entire Callisto client encryption of a
// Callisto entry and returns the 6-tuple to be sent to a Callisto database
// server
func (c *CallistoClient) CreateCallistoTuple(perpID []byte, entry types.CallistoEntry, pubKeys types.LOCPublicKeys, evaluator oprf.OPRFEvaluator) (types.CallistoTuple, error) {
	// Evaluate the OPRF to get P-Hat
	pHat, err := c.getPHatValue(perpID, evaluator)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to evaulate OPRF and get p-hat: %v", err)
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

	return types.CallistoTuple{
		Pi:                                akpiValues.pi,
		LOCCiphertext:                     locCiphertext,
		DLOCCiphertext:                    dlocCiphertext,
		EncryptedEntryDataKeyUnderUserKey: encryptedCallistoEntryData.encryptedEntryDataKeyByU,
		EncryptedEntryData:                encryptedCallistoEntryData.encryptedEntryData,
		EncryptedAssignmentData:           encryptedCallistoEntryData.encryptedAssignmentData,
	}, nil
}

type encryptedCallistoEntry struct {
	encryptedEntryData       types.GCMCiphertext // eEntry value
	encryptedEntryDataKeyByK types.GCMCiphertext // c_e value
	encryptedEntryDataKeyByU types.GCMCiphertext // c_u value

	encryptedAssignmentData       types.GCMCiphertext // eAssign value
	encryptedAssignmentDataKeyByK types.GCMCiphertext // c_a value
}

// encryptEntry performs client-side symmetric encryption operations involved in
// encrypting an entry
func (c *CallistoClient) encryptEntry(entry types.CallistoEntry, akpiValues akpi) (encryptedCallistoEntry, error) {
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
func encryptEntryData(data types.EntryData, pi []byte) (types.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of entry data
	entryDataEncodedBytes, err := encoding.EncodeEntryData(data)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Generate random entry data key: k_e
	entryDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Encrypt entryData to get eEntry
	encryptedEntryData, err := encryption.EncryptAES(entryDataKey, entryDataEncodedBytes, pi)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt entry data: %v", err)
	}

	return encryptedEntryData, entryDataKey, nil
}

// encryptAssignmentData generates a fresh random key and uses it to encrypt
// assignment data. The returned result is both the encrypted assignment data
// and the random key generated.
func encryptAssignmentData(data types.AssignmentData, pi []byte) (types.GCMCiphertext, []byte, error) {
	// Create msgpack encoding of assignment data
	assignmentDataEncodedBytes, err := encoding.EncodeAssignmentData(data)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Generate random assignment data key: k_a
	assignmentDataKey, err := util.GenerateRandomBytes(32)
	if err != nil {
		return types.GCMCiphertext{}, nil, err
	}

	// Encrypt assignmentData to get eAssign
	encryptedAssignmentData, err := encryption.EncryptAES(assignmentDataKey, assignmentDataEncodedBytes, pi)
	if err != nil {
		return types.GCMCiphertext{}, nil, fmt.Errorf("failed to encrypt assignment data: %v", err)
	}

	return encryptedAssignmentData, assignmentDataKey, nil
}

// encryptLOCData forms the c or c_assign tuple (depending on locType) and
// encrypts the necessary data for a LOC
func encryptLOCData(locType types.LOCType, shamirShare *ss.Share, encryptedKey types.GCMCiphertext, locPublicKey *rsa.PublicKey) ([]byte, error) {
	locData := types.LOCData{
		Type:         locType,
		U:            shamirShare.X.Bytes(),
		S:            shamirShare.Y.Bytes(),
		EncryptedKey: encryptedKey,
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

// getPHatValue asks an OPRF evaluator to transform a low-entropy perpetrator ID
// into a pseudorandom value with sufficient entropy
func (c *CallistoClient) getPHatValue(perpID []byte, evaluator oprf.OPRFEvaluator) ([]byte, error) {
	// Create blinded group element M
	blindedElement, err := c.oprfClient.Blind(perpID)
	if err != nil {
		return nil, err
	}

	// Evalulate the OPRF to get Z value
	elems := []gg.GroupElement{blindedElement.M}
	zValues, err := evaluator.EvaluateOPRF(elems)
	if err != nil {
		return nil, err
	}

	// Unblind Z values to get N values
	blindedElements := []oprf.BlindedElement{blindedElement}
	nValues, err := c.oprfClient.Unblind(blindedElements, zValues)
	if err != nil {
		return nil, err
	}

	// Finalize and get resulting P-Hat
	pHat, err := c.oprfClient.Finalize(nValues[0], perpID)
	if err != nil {
		return nil, err
	}

	return pHat, nil
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
