package oprf

import (
	"fmt"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oprf"
	"github.com/alxdavids/voprf-poc/go/oprf/groups"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
)

type OPRFClient struct {
	Ciphersuite string
	client      oprf.Client
}

type BlindedElement struct {
	M groups.GroupElement // Blinded representation of a client input encoded in GG
	R *big.Int            // The blind applied
}

// NewOPRFClient returns an OPRF client that can perform client-side operations
// (client) of the OPRF protocol
func NewOPRFClient(ciphersuite string) (*OPRFClient, error) {
	oprfClient, err := clientSetup(ciphersuite)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal oprf client: %v", err)
	}

	return &OPRFClient{
		Ciphersuite: ciphersuite,
		client:      oprfClient,
	}, nil
}

// Blind creates a blinded group element M by first encoding input to GG using
// H_1 hash function, and then masking it with a random blind
func (c *OPRFClient) Blind(input []byte) (BlindedElement, error) {
	// Create a blinded group element
	m, r, err := c.client.Blind(input)
	if err != nil {
		return BlindedElement{}, fmt.Errorf("failed to blind input: %v", err)
	}

	return BlindedElement{
		M: m,
		R: r,
	}, nil
}

// Unblind takes a list of blinded elements and Z values, and unblinds all
// elements
func (c *OPRFClient) Unblind(blindedElements []BlindedElement, zValues []gg.GroupElement) ([]gg.GroupElement, error) {
	evaluation := oprf.Evaluation{Elements: zValues}
	mValues := make([]gg.GroupElement, len(blindedElements))
	blinds := make([]*big.Int, len(blindedElements))
	for i, e := range blindedElements {
		mValues[i] = e.M
		blinds[i] = e.R
	}

	// Do client unblinding
	nValues, err := c.client.Unblind(evaluation, mValues, blinds)
	if err != nil {
		return nil, fmt.Errorf("failed to unblind: %v", err)
	}
	return nValues, nil
}

// Finalize completes the OPRF procedure by hashing unblinded N values with the
// ciphersuite's defined domain separating label (DST) using the H_2 hash
// function
func (c *OPRFClient) Finalize(nValue gg.GroupElement, input []byte) ([]byte, error) {
	// Finalize with empty auxillary data
	y, err := c.client.Finalize(nValue, input, []byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to finalize: %v", err)
	}
	return y, nil
}

func clientSetup(ciph string) (oprf.Client, error) {
	clientAsParticipant, err := oprf.Client{}.Setup(ciph, ecgroup.GroupCurve{})
	if err != nil {
		return oprf.Client{}, err
	}
	client, err := oprf.CastClient(clientAsParticipant)
	if err != nil {
		return oprf.Client{}, err
	}
	return client, nil
}
