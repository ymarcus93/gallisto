package callisto

import (
	"encoding/hex"
	"fmt"

	"github.com/ymarcus93/gallisto/types"
)

type CallistoTupleMatch struct {
	SharedPiValue []byte
	MatchedTuples []types.CallistoTuple
}

// FindMatches scans a list of Callisto Tuple entries and looks for common pi
// values. If there are >= 2 tuples with the same pi value, a match with the
// tuples and shared pi value is added to the list to be returned. If the
// returned list is nil, no matches were found.
func FindMatches(entries []types.CallistoTuple) ([]CallistoTupleMatch, error) {
	piMap := make(map[string][]types.CallistoTuple)

	// Scan through entries and create pi-->list(tuple mapping) of tuples with
	// common pi value
	for _, e := range entries {
		piAsHexString := hex.EncodeToString(e.Pi)
		tupleList := piMap[piAsHexString]
		tupleList = append(tupleList, e)
		piMap[piAsHexString] = tupleList
	}

	// Create match structs
	var matches []CallistoTupleMatch
	for k, v := range piMap {
		if len(v) > 1 {
			piValue, err := hex.DecodeString(k)
			if err != nil {
				return nil, fmt.Errorf("failed to decode %v: %v", k, err)
			}
			match := CallistoTupleMatch{
				SharedPiValue: piValue,
				MatchedTuples: v,
			}
			matches = append(matches, match)
		}
	}
	return matches, nil
}
