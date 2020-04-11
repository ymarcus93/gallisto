package shamir

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/superarius/shamir"
	"github.com/superarius/shamir/modular"
	helper "github.com/ymarcus93/gallisto/internal/test"
)

func computeShamirShares(aValue, kValue []byte, numToCreate int, t *testing.T) []*shamir.Share {
	shares := make([]*shamir.Share, numToCreate)
	for i := range shares {
		userID := helper.GenerateRandomBytes(32, t)
		share := ComputeShamirShare(aValue, kValue, userID)
		shares[i] = share
	}
	return shares
}

func TestComputeShamirShare(t *testing.T) {
	// Element U
	userID := helper.GenerateRandomBytes(32, t)
	userIDHash := sha256.Sum256(userID)
	elementU := modular.IntFromBytes(userIDHash[:])

	// Element a
	aValue := helper.GenerateRandomBytes(32, t)
	elementA := modular.IntFromBytes(aValue)

	// Element k
	kValue := helper.GenerateRandomBytes(32, t)
	elementK := modular.IntFromBytes(kValue)

	// Compute point s = aU + k
	aTimesU := new(modular.Int).Mul(elementA, elementU)
	elementS := new(modular.Int).Add(aTimesU, elementK)

	// Assert equality
	actualShare := ComputeShamirShare(aValue, kValue, userID)
	assert.Equal(t, &shamir.Share{X: elementU, Y: elementS}, actualShare)
}

func TestFindShamirKValue_IncorrectlyInterpolates(t *testing.T) {
	aValue1 := helper.GenerateRandomBytes(32, t)
	kValue1 := helper.GenerateRandomBytes(32, t)
	kValue1AsModInt := modular.IntFromBytes(kValue1)
	aValue2 := helper.GenerateRandomBytes(32, t)
	kValue2 := helper.GenerateRandomBytes(32, t)
	kValue2AsModInt := modular.IntFromBytes(kValue2)

	share1 := computeShamirShares(aValue1, kValue1, 1, t)
	share2 := computeShamirShares(aValue2, kValue2, 1, t)
	shares := append(share1, share2...)
	foundKValue, err := FindShamirKValue(shares)
	if assert.NoError(t, err) {
		assert.NotEqual(t, kValue1AsModInt, foundKValue)
		assert.NotEqual(t, kValue2AsModInt, foundKValue)
	}
}

func TestFindShamirKValue_CorrectlyInterpolates(t *testing.T) {
	numOfSharesOnSameLine := []int{2, 3, 4, 5, 6, 7, 8, 9, 10}

	for _, numOfShares := range numOfSharesOnSameLine {
		t.Run(fmt.Sprintf("number of shares on same line: %v", numOfShares), func(t *testing.T) {
			aValue := helper.GenerateRandomBytes(32, t)
			kValue := helper.GenerateRandomBytes(32, t)
			shares := computeShamirShares(aValue, kValue, numOfShares, t)
			foundKValue, err := FindShamirKValue(shares)
			if assert.NoError(t, err) {
				expectedKValue := modular.IntFromBytes(kValue)
				assert.Equal(t, expectedKValue, foundKValue)
			}
		})
	}
}
