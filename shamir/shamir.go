package shamir

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/superarius/shamir"
	ff "github.com/superarius/shamir/modular"
)

// Shamir Protocol Errors
var (
	ErrFailedToFindKValue = errors.New("Failed to find k value of polynomial")
)

// CallistoPrime is the prime modulus mentioned in the Callisto paper: 2^256 + 297
const CallistoPrime string = "115792089237316195423570985008687907853269984665640564039457584007913129640233"

func init() {
	// Set prime modulus for the finite field package to CallistoPrime
	prime, err := ff.IntFromString(CallistoPrime, 10)
	if err != nil {
		panic(err.Error())
	}
	ff.SetP(prime)
}

// FindShamirKValue uses a Vandermonde matrix to interpolate a polynomial and
// finds the y-intercept of the polynomial if possible
func FindShamirKValue(shares []*shamir.Share) (*ff.Int, error) {
	result, err := shamir.InterpolatePolynomial(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate polynomial: %v", err)
	}

	yIntercept := result[0]
	if yIntercept.AsBig() == ff.NewInt(0).AsBig() {
		return nil, ErrFailedToFindKValue
	}
	return yIntercept, nil
}

// ComputeShamirShare computes a (U,s) SSSS share given a userID and KDF derived
// values: a, k
func ComputeShamirShare(aValue, kValue, userId []byte) *shamir.Share {
	// Hash the userID
	userIdHash := sha256Sum(userId)

	elementA := ff.IntFromBytes(aValue)
	elementK := ff.IntFromBytes(kValue)
	elementU := ff.IntFromBytes(userIdHash)

	// Compute point s = aU + k
	elementAMultU := new(ff.Int).Mul(elementA, elementU)
	elementS := new(ff.Int).Add(elementAMultU, elementK)

	return &shamir.Share{X: elementU, Y: elementS}
}

func sha256Sum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
