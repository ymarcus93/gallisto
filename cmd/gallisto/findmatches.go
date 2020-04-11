package main

import (
	"encoding/hex"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/ymarcus93/gallisto/internal/encryption"
	"github.com/ymarcus93/gallisto/protocol"
	"github.com/ymarcus93/gallisto/types"
)

func findMatches() error {

	tuples := make([]protocol.Matchable, len(callistoTuples))
	for i, tup := range callistoTuples {
		tuples[i] = tup
	}
	matches, err := protocol.FindMatches(tuples)
	if err != nil {
		return err
	}

	if matches == nil {
		fmt.Println("no matches found")
		return nil
	}

	var totalEntries int
	for _, match := range matches {
		totalEntries = totalEntries + len(match.MatchedEntries)
	}

	fmt.Printf("found %v match(es) with distinct pi values!\n", len(matches))
	fmt.Printf("total entries found across all pi values: %v\n", totalEntries)

	matchedTuples, err := matchSelector(matches)
	if err != nil {
		return err
	}

	for _, m := range matchedTuples {
		fmt.Printf("\ndecrypted data for pi: %v\n", m.piValue)
		err = decryptTuples(m.callistoTuplesSelected)
		if err != nil {
			return err
		}
	}

	return nil
}

func convertMatchPiValuesToHex(matches []protocol.PiMatch) ([]string, map[string]protocol.PiMatch) {
	hexValues := make([]string, len(matches))
	reverseLookup := make(map[string]protocol.PiMatch, 0)
	for i, match := range matches {
		piAsHex := hex.EncodeToString(match.SharedPiValue)
		hexValues[i] = piAsHex
		reverseLookup[piAsHex] = match
	}
	return hexValues, reverseLookup
}

type selectedMatch struct {
	piValue                string
	callistoTuplesSelected []types.CallistoTuple
}

func matchSelector(matches []protocol.PiMatch) ([]selectedMatch, error) {
	matchPiValues, hexToMatchMap := convertMatchPiValuesToHex(matches)
	matchSelectionPrompt := &survey.MultiSelect{
		Message: "Which matches do you want to decrypt?:",
		Options: matchPiValues,
		Default: matchPiValues[0],
	}
	var selectedMatches []string
	promptError := survey.AskOne(matchSelectionPrompt, &selectedMatches, survey.WithValidator(survey.Required))
	if promptError != nil {
		return nil, promptError
	}

	parsedSelectedMatches := make([]protocol.PiMatch, len(selectedMatches))
	for i, selectedMatchStr := range selectedMatches {
		selectedMatch := hexToMatchMap[selectedMatchStr]
		parsedSelectedMatches[i] = selectedMatch
	}

	allSelectedMatches := make([]selectedMatch, len(parsedSelectedMatches))

	for i, match := range parsedSelectedMatches {
		callistoTuplesSelected := make([]types.CallistoTuple, 0)
		for _, entry := range match.MatchedEntries {
			callistoTuple := (entry).(types.CallistoTuple)
			callistoTuplesSelected = append(callistoTuplesSelected, callistoTuple)
		}
		constructed := selectedMatch{
			callistoTuplesSelected: callistoTuplesSelected,
			piValue:                hex.EncodeToString(match.SharedPiValue),
		}
		allSelectedMatches[i] = constructed
	}
	return allSelectedMatches, nil
}

func decryptTuples(tuples []types.CallistoTuple) error {
	dlocCiphertexts := make([][]byte, len(tuples))
	locCiphertexts := make([][]byte, len(tuples))
	encryptedAssignmentData := make([]encryption.GCMCiphertext, len(tuples))
	encryptedEntryData := make([]encryption.GCMCiphertext, len(tuples))

	for i, tuple := range tuples {
		dlocCiphertexts[i] = tuple.DLOCCiphertext()
		locCiphertexts[i] = tuple.LOCCiphertext()
		encryptedAssignmentData[i] = tuple.EncryptedAssignmentData()
		encryptedEntryData[i] = tuple.EncryptedEntryData()
	}

	assignmentResults, err := protocol.DecryptAssignmentData(dlocCiphertexts, encryptedAssignmentData, pubkeys.dlocKeys.PrivateKey)
	if err != nil {
		return err
	}
	fmt.Println("\ndecrypted assignment data:")
	for _, d := range assignmentResults {
		// fmt.Printf("%+v\n", d)
		fmt.Println(prettyPrint(d))
	}

	entryResults, err := protocol.DecryptEntryData(locCiphertexts, encryptedEntryData, pubkeys.locKeys.PrivateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("\ndecrypted entry data:")
	for _, d := range entryResults {
		fmt.Println(prettyPrint(d))
		// fmt.Printf("%+v\n", d)
	}
	return nil
}
