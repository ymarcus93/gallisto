package shamir

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/superarius/shamir/modular"
	helper "github.com/ymarcus93/gallisto/internal/test"
)

func computeShamirShares(aValue, kValue []byte, numToCreate int, t *testing.T) []*ShamirShare {
	shares := make([]*ShamirShare, numToCreate)
	for i := range shares {
		userID := helper.GenerateRandomBytes(32, t)
		share := ComputeShamirShare(aValue, kValue, userID)
		shares[i] = share
	}
	return shares
}

func computeShamirSharesWithUserID(aValue, kValue, userID []byte, numToCreate int, t *testing.T) []*ShamirShare {
	shares := make([]*ShamirShare, numToCreate)
	for i := range shares {
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
	assert.Equal(t, &ShamirShare{X: elementU, Y: elementS}, actualShare)
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

func TestShamirValueHex(t *testing.T) {
	tests := map[string]struct {
		sameAValue        bool
		sameKValue        bool
		sameUserID        bool
		shouldTheyBeEqual bool
	}{
		"hex should be equal when same share": {
			sameAValue:        true,
			sameKValue:        true,
			sameUserID:        true,
			shouldTheyBeEqual: true,
		},
		"hex should not be equal when different user id": {
			sameAValue:        true,
			sameKValue:        true,
			sameUserID:        false,
			shouldTheyBeEqual: false,
		},
		"hex should not be equal when different s value": {
			sameAValue:        false,
			sameKValue:        false,
			sameUserID:        true,
			shouldTheyBeEqual: false,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			aValue1 := helper.GenerateRandomBytes(32, t)
			kValue1 := helper.GenerateRandomBytes(32, t)
			userID1 := helper.GenerateRandomBytes(32, t)

			var aValue2, kValue2, userID2 []byte

			if test.sameAValue {
				aValue2 = aValue1
			} else {
				aValue2 = helper.GenerateRandomBytes(32, t)
			}

			if test.sameKValue {
				kValue2 = kValue1
			} else {
				kValue2 = helper.GenerateRandomBytes(32, t)
			}

			if test.sameUserID {
				userID2 = userID1
			} else {
				userID2 = helper.GenerateRandomBytes(32, t)
			}

			share1 := computeShamirSharesWithUserID(aValue1, kValue1, userID1, 1, t)[0]
			share2 := computeShamirSharesWithUserID(aValue2, kValue2, userID2, 1, t)[0]

			if test.shouldTheyBeEqual {
				assert.Equal(t, share1.Hex(), share2.Hex())
			} else {
				assert.NotEqual(t, share1.Hex(), share2.Hex())
			}
		})
	}
}

func TestFindShamirKValue_CorrectlyInterpolatesWhenMixed(t *testing.T) {
	aValue := helper.GenerateRandomBytes(32, t)
	kValue := helper.GenerateRandomBytes(32, t)
	tests := []struct {
		mapUserToEntriesToCreate map[string]int
	}{
		{map[string]int{"User 1": 1, "User 2": 1}},
		{map[string]int{"User 1": 2, "User 2": 1}},
		{map[string]int{"User 1": 2, "User 2": 2}},
		{map[string]int{"User 1": 1, "User 2": 1, "User 3": 1}},
		{map[string]int{"User 1": 1, "User 2": 1, "User 3": 2}},
		{map[string]int{"User 1": 2, "User 2": 1, "User 3": 1}},
	}

	for i, test := range tests {
		totalEntries := 0
		for _, v := range test.mapUserToEntriesToCreate {
			totalEntries = totalEntries + v
		}
		numOfUsers := len(test.mapUserToEntriesToCreate)
		testName := fmt.Sprintf("Test %v: %v users, %v entries", i, numOfUsers, totalEntries)
		t.Run(testName, func(t *testing.T) {
			testInput := make([]*ShamirShare, 0)
			for k, v := range test.mapUserToEntriesToCreate {
				t.Logf("%v creates %v entries", k, v)
				userID := helper.GenerateRandomBytes(32, t)
				entries := computeShamirSharesWithUserID(aValue, kValue, userID, v, t)
				testInput = append(testInput, entries...)
			}
			foundKValue, err := FindShamirKValue(testInput)
			if assert.NoError(t, err) {
				expectedKValue := modular.IntFromBytes(kValue)
				assert.Equal(t, expectedKValue, foundKValue)
			}
		})
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
