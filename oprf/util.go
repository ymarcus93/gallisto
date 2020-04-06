package oprf

import (
	"fmt"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
)

// ParseCiphersuiteString creates an OPRF ciphersuite from a string
func ParseCiphersuiteString(ciphersuite string) (gg.Ciphersuite, error) {
	suite, err := gg.Ciphersuite{}.FromString(ciphersuite, ecgroup.GroupCurve{})
	if err != nil {
		return gg.Ciphersuite{}, fmt.Errorf("failed to parse ciphersuite string %v: %v", ciphersuite, err)
	}
	return suite, nil
}
