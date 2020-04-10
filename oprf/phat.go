package oprf

import (
	"fmt"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/ymarcus93/gallisto/types"
)

// OPRFEvaluator represents the holder of the OPRF key who can evaluate
// arbitrary inputs
type OPRFEvaluator interface {
	EvaluateOPRF(blindedInputValues []gg.GroupElement) ([]gg.GroupElement, error)
}

// PHatComputer encapuslates both an OPRF client (the one who has input) and an
// evaluator (the one who holds the key) which when combined can compute p-hat
// values
type PHatComputer struct {
	oprfClient    *OPRFClient
	oprfEvaluator OPRFEvaluator
}

// Returns a computer that can compute p-hat values. P-hat values are computed
// by using an OPRF
func NewPHatComputer(oprfEvaluator OPRFEvaluator) (*PHatComputer, error) {
	oprfClient, err := NewOPRFClient(types.OPRF_CIPHERSUITE)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPRF client: %v", err)
	}

	return &PHatComputer{
		oprfClient:    oprfClient,
		oprfEvaluator: oprfEvaluator,
	}, nil
}

// GetPHatValue asks an OPRF evaluator to transform a low-entropy perpetrator ID
// into a pseudorandom value with sufficient entropy
func (p *PHatComputer) GetPHatValue(perpID []byte) ([]byte, error) {
	// Create blinded group element M
	blindedElement, err := p.oprfClient.Blind(perpID)
	if err != nil {
		return nil, err
	}

	// Evalulate the OPRF to get Z value
	elems := []gg.GroupElement{blindedElement.M}
	zValues, err := p.oprfEvaluator.EvaluateOPRF(elems)
	if err != nil {
		return nil, err
	}

	// Unblind Z values to get N values
	blindedElements := []BlindedElement{blindedElement}
	nValues, err := p.oprfClient.Unblind(blindedElements, zValues)
	if err != nil {
		return nil, err
	}

	// Finalize and get resulting P-Hat
	pHat, err := p.oprfClient.Finalize(nValues[0], perpID)
	if err != nil {
		return nil, err
	}

	return pHat, nil
}
