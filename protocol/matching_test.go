package protocol

import (
	"fmt"
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
				SharedPiValue:                     piOne,
				MatchedEntries:                    createPisWithDistinctUserIDs(2, piOne, t),
				MatchedEntriesWithDistinctUserIDs: createPisWithDistinctUserIDs(2, piOne, t),
			}},
		},
		"one match of length 3": {
			input: createPisWithDistinctUserIDs(3, piOne, t),
			expectedOutput: []PiMatch{{
				SharedPiValue:                     piOne,
				MatchedEntries:                    createPisWithDistinctUserIDs(3, piOne, t),
				MatchedEntriesWithDistinctUserIDs: createPisWithDistinctUserIDs(3, piOne, t),
			}},
		},
		"two matches (distinct pi values)": {
			input: append(createPisWithDistinctUserIDs(2, piOne, t), createPisWithDistinctUserIDs(2, piTwo, t)...),
			expectedOutput: []PiMatch{{
				SharedPiValue:                     piOne,
				MatchedEntries:                    createPisWithDistinctUserIDs(2, piOne, t),
				MatchedEntriesWithDistinctUserIDs: createPisWithDistinctUserIDs(2, piOne, t),
			}, {
				SharedPiValue:                     piTwo,
				MatchedEntries:                    createPisWithDistinctUserIDs(2, piTwo, t),
				MatchedEntriesWithDistinctUserIDs: createPisWithDistinctUserIDs(2, piTwo, t),
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
					assert.ElementsMatch(t, test.expectedOutput[i].MatchedEntriesWithDistinctUserIDs, o.MatchedEntriesWithDistinctUserIDs)
				}
			}
		})
	}
}

func TestFindMatchesCorrectNumberOfMatchesWithDistinctUserIDs(t *testing.T) {
	pi := helper.GenerateRandomBytes(SIZE_BYTES, t)
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
			testInput := make([]Matchable, 0)
			for k, v := range test.mapUserToEntriesToCreate {
				t.Logf("%v creates %v entries", k, v)
				entries := createPisWithFixedUserID(v, pi, t)
				testInput = append(testInput, entries...)
			}
			output, err := FindMatches(testInput)
			if assert.NoError(t, err) {
				assert.Len(t, output, 1)
				match := output[0]
				assert.ElementsMatch(t, testInput, match.MatchedEntries)
				assert.Len(t, match.MatchedEntriesWithDistinctUserIDs, numOfUsers)
			}
		})
	}
}
