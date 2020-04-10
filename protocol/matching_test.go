package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	helper "github.com/ymarcus93/gallisto/test"
)

const PI_SIZE = 32

type testPi struct {
	pi []byte
}

func (f testPi) Pi() []byte {
	return f.pi
}

func createRandomPis(numToCreate int, t *testing.T) []HasPi {
	entries := make([]HasPi, numToCreate)
	for i := 0; i < numToCreate; i++ {
		randBytes := helper.GenerateRandomBytes(PI_SIZE, t)
		entries[i] = testPi{pi: randBytes}
	}
	return entries
}

func createFixedPis(numToCreate int, sharedPiValue []byte) []HasPi {
	entries := make([]HasPi, numToCreate)
	for i := 0; i < numToCreate; i++ {
		entries[i] = testPi{pi: sharedPiValue}
	}
	return entries
}

func TestFindMatches(t *testing.T) {
	// Generate some fixed pi values
	piOne := helper.GenerateRandomBytes(PI_SIZE, t)
	piTwo := helper.GenerateRandomBytes(PI_SIZE, t)

	tests := map[string]struct {
		input          []HasPi
		expectedOutput []PiMatch
	}{
		"zero matches": {
			input:          createRandomPis(2, t),
			expectedOutput: nil,
		},
		"one match of length 2": {
			input: createFixedPis(2, piOne),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createFixedPis(2, piOne),
			}},
		},
		"one match of length 3": {
			input: createFixedPis(3, piOne),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createFixedPis(3, piOne),
			}},
		},
		"two matches (distinct pi values)": {
			input: append(createFixedPis(2, piOne), createFixedPis(2, piTwo)...),
			expectedOutput: []PiMatch{{
				SharedPiValue:  piOne,
				MatchedEntries: createFixedPis(2, piOne),
			}, {
				SharedPiValue:  piTwo,
				MatchedEntries: createFixedPis(2, piTwo),
			}},
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			actualOutput, err := FindMatches(test.input)
			if assert.NoError(t, err) {
				assert.Equal(t, test.expectedOutput, actualOutput)
			}
		})
	}
}
