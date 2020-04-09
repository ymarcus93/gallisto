package protocol

import (
	"encoding/hex"
	"fmt"
)

type PiMatch struct {
	SharedPiValue  []byte
	MatchedEntries []HasPi
}

type HasPi interface {
	Pi() []byte
}

// FindMatches returns a list of Pi matches. A match is defined as >= 2 entries
// sharing the same pi value. The returned list is nil if no matches were found.
func FindMatches(entries []HasPi) ([]PiMatch, error) {
	piMap := make(map[string][]HasPi)

	// Scan through entries and create pi-->list(entries) mapping of entries
	// with common pi value
	for _, e := range entries {
		piAsHexString := hex.EncodeToString(e.Pi())
		tupleList := piMap[piAsHexString]
		tupleList = append(tupleList, e)
		piMap[piAsHexString] = tupleList
	}

	// Create match structs
	var matches []PiMatch
	for k, v := range piMap {
		if len(v) >= 2 {
			piValue, err := hex.DecodeString(k)
			if err != nil {
				return nil, fmt.Errorf("failed to decode %v: %v", k, err)
			}
			match := PiMatch{
				SharedPiValue:  piValue,
				MatchedEntries: v,
			}
			matches = append(matches, match)
		}
	}
	return matches, nil
}
