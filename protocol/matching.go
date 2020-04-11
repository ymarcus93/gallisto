package protocol

import (
	"encoding/hex"
	"fmt"
)

type PiMatch struct {
	SharedPiValue  []byte
	MatchedEntries []Matchable
}

type Matchable interface {
	Pi() []byte
	UserID() []byte
}

// FindMatches returns a list of Pi matches. A match is defined as >= 2 entries
// sharing the same pi value, but different user IDs. The returned list is nil
// if no matches were found.
func FindMatches(entries []Matchable) ([]PiMatch, error) {
	piMap := make(map[string][]Matchable)

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
			// If there are only common pi values under the same user, then we
			// return zero matches as a match requires distinct users with the
			// same pi value
			if !existsUniqueIDs(v) {
				continue
			}
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

func existsUniqueIDs(entries []Matchable) bool {
	seen := make(map[string]struct{}, 0)
	for _, e := range entries {
		userIDAsHexString := hex.EncodeToString(e.UserID())
		seen[userIDAsHexString] = struct{}{}
	}

	return len(seen) > 1
}
