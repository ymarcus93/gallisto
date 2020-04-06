package callisto

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/oprf"
	"github.com/ymarcus93/gallisto/shamir"
	"github.com/ymarcus93/gallisto/types"
	"github.com/ymarcus93/gallisto/util"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/hkdf"
)

type CallistoClient struct {
	UserID     []byte
	userKey    []byte
	oprfClient *oprf.OPRFClient
}

type AKPi struct {
	A  []byte
	K  []byte
	Pi []byte
}

type CallistoEntry struct {
	PerpID         []byte
	EntryData      types.EntryData
	AssignmentData types.AssignmentData
}

type LOCPublicKeys struct {
	LOCPublicKey  *rsa.PublicKey
	DLOCPublicKey *rsa.PublicKey
}

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

func (c *CallistoClient) CreateCallistoTuple(entry CallistoEntry, pubKeys LOCPublicKeys, evaluator oprf.OPRFEvaluator) (types.CallistoTuple, error) {
	// Evaluate the OPRF to get P-Hat
	pHat, err := c.GetPHatValue(entry.PerpID, evaluator)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to evaulate OPRF and get p-hat: %v", err)
	}

	// Derive from P-Hat three 32-byte pseudorandom values
	akpiValues, err := c.DeriveAKPiValues(pHat)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to derived a, k, and pi: %v", err)
	}

	// Evaluate shamir polynomial y = ax + k at x = U to get y = s
	shamirShare := shamir.ComputeShamirShare(akpiValues.A, akpiValues.K, c.UserID)

	// Encrypt entry data
	encryptedEntryData, entryDataKey, err := encryption.EncryptEntryData(entry.EntryData, akpiValues.Pi)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encrypt entry data: %v", err)
	}

	// cE
	encryptedEntryDataKeyByK, err := encryption.EncryptAES(akpiValues.K, entryDataKey, akpiValues.Pi)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to create c_e: %v", err)
	}

	// cU
	encryptedEntryDataKeyByU, err := encryption.EncryptAES(akpiValues.K, entryDataKey, akpiValues.Pi)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to create c_u: %v", err)
	}

	// c
	locData := types.LOCData{
		U:                     shamirShare.X.AsBig(),
		S:                     shamirShare.X.AsBig(),
		EncryptedEntryDataKey: encryptedEntryDataKeyByK,
	}

	// Create msgpack encoding of LOC data
	locDataEncodedBytes, err := msgpack.Marshal(&locData)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encode LOC data: %v", err)
	}

	locCiphertext, err := encryption.EncryptRSA(locDataEncodedBytes, pubKeys.LOCPublicKey)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encrypt locData to LOC: %v", err)
	}

	// Encrypt entry data
	encryptedAssignmentData, assignmentDataKey, err := encryption.EncryptAssignmentData(entry.AssignmentData, akpiValues.Pi)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encrypt assignment data: %v", err)
	}

	// cA
	encryptedAssignmentDataKey, err := encryption.EncryptAES(akpiValues.K, assignmentDataKey, akpiValues.Pi)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to create c_a: %v", err)
	}

	// c_assign
	dlocData := types.DLOCData{
		U:                          shamirShare.X.AsBig(),
		S:                          shamirShare.X.AsBig(),
		EncryptedAssignmentDataKey: encryptedAssignmentDataKey,
	}

	// Create msgpack encoding of DLOC data
	dlocDataEncodedBytes, err := msgpack.Marshal(&dlocData)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encode DLOC data: %v", err)
	}

	dlocCiphertext, err := encryption.EncryptRSA(dlocDataEncodedBytes, pubKeys.DLOCPublicKey)
	if err != nil {
		return types.CallistoTuple{}, fmt.Errorf("failed to encrypt locData to LOC: %v", err)
	}

	return types.CallistoTuple{
		Pi:                                akpiValues.Pi,
		LOCCiphertext:                     locCiphertext,
		DLOCCiphertext:                    dlocCiphertext,
		EncryptedEntryDataKeyUnderUserKey: encryptedEntryDataKeyByU,
		EncryptedEntryData:                encryptedEntryData,
		EncryptedAssignmentData:           encryptedAssignmentData,
	}, nil
}

func (c *CallistoClient) GetPHatValue(perpID []byte, evaluator oprf.OPRFEvaluator) ([]byte, error) {
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

// DeriveAKPiValues derives the triple: (a, k, pi) from an evaluated OPRF
// function
func (c *CallistoClient) DeriveAKPiValues(pHat []byte) (AKPi, error) {
	// Underlying hash function for HMAC.
	hash := sha256.New
	hkdf := hkdf.New(hash, pHat, nil, nil)

	// Generate three 256-bit derived keys.
	var keys [][]byte
	for i := 0; i < 3; i++ {
		key := make([]byte, 32)
		if _, err := io.ReadFull(hkdf, key); err != nil {
			return AKPi{}, fmt.Errorf("failed to derive AKP values at index %v: %v", i, err)
		}
		keys = append(keys, key)
	}

	return AKPi{
		A:  keys[0],
		K:  keys[1],
		Pi: keys[2],
	}, nil
}
