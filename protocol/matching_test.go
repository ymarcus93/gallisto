package protocol

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	helper "github.com/ymarcus93/gallisto/internal/test"
)

const SIZE_BYTES = 32

type testPi struct {
	pi     []byte
	userId []byte
}

func (f testPi) Pi() []byte {
	return f.pi
}

func (f testPi) UserID() []byte {
	return f.userId
}

func createPisWithFixedUserID(numToCreate int, sharedPiValue []byte, t *testing.T) []Matchable {
	entries := make([]Matchable, numToCreate)
	fixedUserId := helper.GenerateRandomBytes(SIZE_BYTES, t)
	for i := 0; i < numToCreate; i++ {
		entries[i] = testPi{pi: sharedPiValue, userId: fixedUserId}
	}
	return entries
}

func createPisWithDistinctUserIDs(numToCreate int, sharedPiValue []byte, t *testing.T) []Matchable {
	entries := make([]Matchable, numToCreate)
	userID := []byte("userID")
	for i := 0; i < numToCreate; i++ {
		entries[i] = testPi{pi: sharedPiValue, userId: userID}
		// Create distinct userIDs in a consistent way
		userID = []byte("userID" + strconv.Itoa(i+1))
	}
	return entries
}

func TestFindMatches(t *testing.T) {
	// Generate some fixed pi values
	piOne := helper.GenerateRandomBytes(SIZE_BYTES, t)
	piTwo := helper.GenerateRandomBytes(SIZE_BYTES, t)

	tests := map[string]struct {
		input          []Matchable
		expectedOutput []PiMatch
	}{
		"zero matches when no shared pi": {
			input:          append(createPisWithDistinctUserIDs(1, piOne, t), createPisWithDistinctUserIDs(1, piTwo, t)...),
			expectedOutput: nil,
		},
		"zero matches when there is shared pi but same user reported": {
			input:          createPisWithFixedUserID(5, piOne, t),
			expectedOutput: nil,
		},
		"one match of length 2": {
			input: createPisWithDistinctUserIDs(2, piOne, t),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createPisWithDistinctUserIDs(2, piOne, t),
			}},
		},
		"one match of length 3": {
			input: createPisWithDistinctUserIDs(3, piOne, t),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createPisWithDistinctUserIDs(3, piOne, t),
			}},
		},
		"two matches (distinct pi values)": {
			input: append(createPisWithDistinctUserIDs(2, piOne, t), createPisWithDistinctUserIDs(2, piTwo, t)...),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createPisWithDistinctUserIDs(2, piOne, t),
			}, {
				SharedPiValue:  piTwo,
				MatchedEntries: createPisWithDistinctUserIDs(2, piTwo, t),
			}},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			actualOutput, err := FindMatches(test.input)
			if assert.NoError(t, err) {
				for i, o := range actualOutput {
					assert.Equal(t, test.expectedOutput[i].SharedPiValue, o.SharedPiValue)
					assert.ElementsMatch(t, test.expectedOutput[i].MatchedEntries, o.MatchedEntries)
				}
			}
		})
	}
}
