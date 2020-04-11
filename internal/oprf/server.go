package oprf

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oprf"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
)

type OPRFServer struct {
	Ciphersuite string
	server      oprf.Server
}

// NewOPRFServer returns an OPRF server that can perform server-side operations
// (prover) of the OPRF protocol
func NewOPRFServer(ciphersuite string, secretKey oprf.SecretKey) (*OPRFServer, error) {
	oprfServer, err := serverSetup(ciphersuite)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal oprf server: %v", err)
	}
	oprfServer = oprfServer.SetSecretKey(secretKey)

	return &OPRFServer{
		Ciphersuite: ciphersuite,
		server:      oprfServer,
	}, nil
}

// GenerateKey returns a random OPRF key to be used by an OPRF server
func GenerateKey(ciphersuite string) (oprf.SecretKey, error) {
	suite, err := ParseCiphersuiteString(ciphersuite)
	if err != nil {
		return oprf.SecretKey{}, err
	}

	sk, err := oprf.SecretKey{}.New(suite.POG())
	if err != nil {
		return oprf.SecretKey{}, fmt.Errorf("failed to generate server key: %v", err)
	}
	return sk, nil
}

// EvaluateOPRF computes the Z value of all blinded inputs by using the server's secret
// key
func (s *OPRFServer) EvaluateOPRF(blindedInputValues []gg.GroupElement) ([]gg.GroupElement, error) {
	eval, err := s.server.Eval(blindedInputValues)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate OPRF: %v", err)
	}
	return eval.Elements, nil
}

// KeyToHex returns the hex-encoded representaton of the sercet key: k, and
// public key: Y = kG, where G is the generator of GG
func (s *OPRFServer) KeyToHex() (string, string, error) {
	pubKey, err := s.server.SecretKey().PubKey.Serialize()
	if err != nil {
		return "", "", fmt.Errorf("failed to serialize public key: %v", err)
	}
	k := s.server.SecretKey().K.Bytes()

	pubKeyHex := hex.EncodeToString(pubKey)
	kValueHex := hex.EncodeToString(k)

	return kValueHex, pubKeyHex, nil
}

// KeyFromHex converts a hex-encoded representation of a secret key into an
// oprf.SecretKey to be used by an OPRF server
func KeyFromHex(ciphersuite, kValueHex, pubKeyValueHex string) (oprf.SecretKey, error) {
	// Decode K value
	decodedKeyBytes, err := hex.DecodeString(kValueHex)
	if err != nil {
		return oprf.SecretKey{}, fmt.Errorf("failed to decode kValueHex %v: %v", kValueHex, err)
	}
	decodedKeyAsBigInt := new(big.Int).SetBytes(decodedKeyBytes)

	// Decode PubKey
	decodedPubKeyBytes, err := hex.DecodeString(pubKeyValueHex)
	if err != nil {
		return oprf.SecretKey{}, fmt.Errorf("failed to decode pubKeyValueHex %v: %v", pubKeyValueHex, err)
	}

	suite, err := ParseCiphersuiteString(ciphersuite)
	if err != nil {
		return oprf.SecretKey{}, err
	}
	decodedPublicKey, err := gg.CreateGroupElement(suite.POG()).Deserialize(decodedPubKeyBytes)
	if err != nil {
		return oprf.SecretKey{}, fmt.Errorf("failed to deserialize decodedPublicKey bytes into group element: %v", err)
	}

	return oprf.SecretKey{K: decodedKeyAsBigInt, PubKey: decodedPublicKey}, nil
}

func serverSetup(ciphersuite string) (oprf.Server, error) {
	serverAsParticipant, err := oprf.Server{}.Setup(ciphersuite, ecgroup.GroupCurve{})
	if err != nil {
		return oprf.Server{}, err
	}
	server, err := oprf.CastServer(serverAsParticipant)
	if err != nil {
		return oprf.Server{}, err
	}
	return server, nil
}
