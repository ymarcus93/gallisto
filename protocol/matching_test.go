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

// Test for issue: https://github.com/ymarcus93/gallisto/issues/20
func TestFindMatches_Issue20(t *testing.T) {
	// Create two entries on the same pi value with the same userId
	piOne := helper.GenerateRandomBytes(SIZE_BYTES, t)
	matchablesOne := createPisWithFixedUserID(2, piOne, t)

	// Create a new entry on a different pi value with a different userId
	piTwo := helper.GenerateRandomBytes(SIZE_BYTES, t)
	matchablesTwo := createPisWithDistinctUserIDs(1, piTwo, t)

	// Create a new entry from first user on the newly created pi value
	userIdOne := matchablesOne[0].UserID()
	thirdMatch := testPi{pi: piTwo, userId: userIdOne}

	// We should have a match on piTwo
	expectedMatchedEntries := append(matchablesTwo, thirdMatch)
	expectedOutput := []PiMatch{{
		SharedPiValue:  piTwo,
		MatchedEntries: expectedMatchedEntries,
	}}

	matches := append(matchablesOne, matchablesTwo...)
	actualOutput, err := FindMatches(append(matches, thirdMatch))
	if assert.NoError(t, err) {
		assert.Equal(t, expectedOutput, actualOutput)
	}
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
				assert.ElementsMatch(t, test.expectedOutput, actualOutput)
			}
		})
	}
}
