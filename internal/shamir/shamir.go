package shamir

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/superarius/shamir"
	ff "github.com/superarius/shamir/modular"
)

// CallistoPrime is the prime modulus mentioned in the Callisto paper: 2^256 + 297
const CallistoPrime string = "115792089237316195423570985008687907853269984665640564039457584007913129640233"

type ShamirShare shamir.Share

func (s *ShamirShare) Hex() string {
	xAsHex := hex.EncodeToString(s.X.AsBig().Bytes())
	yAsHex := hex.EncodeToString(s.Y.AsBig().Bytes())
	return xAsHex + yAsHex
}

func init() {
	// Set prime modulus for the finite field package to CallistoPrime
	prime, err := ff.IntFromString(CallistoPrime, 10)
	if err != nil {
		panic(err.Error())
	}
	ff.SetP(prime)
}

func filterForUniqueShares(shares []*ShamirShare) []*ShamirShare {
	uniqueShares := make([]*ShamirShare, 0)
	mapShares := make(map[string]struct{})

	for _, share := range shares {
		shareAsHex := share.Hex()
		if _, ok := mapShares[shareAsHex]; !ok {
			mapShares[shareAsHex] = struct{}{}
			uniqueShares = append(uniqueShares, share)
		}
	}

	return uniqueShares
}

func interpolate(shares []*ShamirShare) ([]*ff.Int, error) {
	shamirPackageShares := make([]*shamir.Share, len(shares))
	for i, share := range shares {
		shamirPackageShares[i] = (*shamir.Share)(share)
	}

	return shamir.InterpolatePolynomial(shamirPackageShares)
}

// FindShamirKValue uses a Vandermonde matrix to interpolate a polynomial and
// finds the y-intercept of the polynomial if possible
func FindShamirKValue(shares []*ShamirShare) (*ff.Int, error) {
	// If we don't filter for unique shares, we run into a problem where if
	// there are >= 2 shares with the same X value (i.e. same user reported more
	// than once on same perp), interpolation will fail. It even fails if there
	// is a valid share from another user (different X value).
	uniqueShares := filterForUniqueShares(shares)
	result, err := interpolate(uniqueShares)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate polynomial: %v", err)
	}

	yIntercept := result[0]
	return yIntercept, nil
}

// ComputeShamirShare computes a (U,s) SSSS share given a userID and KDF derived
// values: a, k
func ComputeShamirShare(aValue, kValue, userId []byte) *ShamirShare {
	// Hash the userID
	userIdHash := sha256Sum(userId)

	elementA := ff.IntFromBytes(aValue)
	elementK := ff.IntFromBytes(kValue)
	elementU := ff.IntFromBytes(userIdHash)

	// Compute point s = aU + k
	elementAMultU := new(ff.Int).Mul(elementA, elementU)
	elementS := new(ff.Int).Add(elementAMultU, elementK)

	return &ShamirShare{X: elementU, Y: elementS}
}

func sha256Sum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
