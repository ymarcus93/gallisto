package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ymarcus93/gallisto/util"
)

const PI_SIZE = 32

type randomPi struct{}

func (r randomPi) Pi() []byte {
	randBytes, err := util.GenerateRandomBytes(PI_SIZE)
	if err != nil {
		panic(err)
	}
	return randBytes
}

type fixedPi struct {
	pi []byte
}

func (f fixedPi) Pi() []byte {
	return f.pi
}

func createFixedPis(numToCreate int, sharedPiValue []byte) []HasPi {
	entries := make([]HasPi, numToCreate)
	for i := 0; i < numToCreate; i++ {
		entries[i] = fixedPi{pi: sharedPiValue}
	}
	return entries
}

func TestFindMatches(t *testing.T) {
	// Generate some fixed pi values
	piOne, err := util.GenerateRandomBytes(PI_SIZE)
	if err != nil {
		t.Error(err)
	}
	piTwo, err := util.GenerateRandomBytes(PI_SIZE)
	if err != nil {
		t.Error(err)
	}

	tests := map[string]struct {
		input          []HasPi
		expectedOutput []PiMatch
	}{
		"zero matches": {
			input:          []HasPi{randomPi{}, randomPi{}},
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
		t.Logf("Running test case: %s", testName)
		actualOutput, err := FindMatches(test.input)
		if assert.NoError(t, err) {
			assert.Equal(t, test.expectedOutput, actualOutput)
		}
	}
}
