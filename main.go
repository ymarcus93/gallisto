package main

import (
	"bytes"
	"fmt"

	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/oprf"
	"github.com/ymarcus93/gallisto/protocol"
	"github.com/ymarcus93/gallisto/protocol/client"
	"github.com/ymarcus93/gallisto/types"
)

func main() {
	// Deterministic OPRF key for testing purposes
	key, err := oprf.KeyFromHex(
		types.OPRF_CIPHERSUITE,
		"f8b9acbf72f204f931ac5b1c987b46502e864ad9c80a41ed2a3e1d01e149d280c69bcc5bdefa53518c83c0e89359b5f88606bb4537f6dd68ab2304362b28ec8cb1",
		"020166481786d499f18ef0a2e510a1ea42563e4d30d7262bcf4080efe6faf0a49e7ae6db123da6d3b834460bad37115b23b45a68ded63fdaaeeb1140aaa7552187b84b",
	)
	if err != nil {
		panic(err)
	}
	oprfServer, err := oprf.NewOPRFServer(types.OPRF_CIPHERSUITE, key)
	if err != nil {
		panic(err)
	}

	// Encapsulate both the OPRF client and server into one computer of PHats
	phatComputer, err := oprf.NewPHatComputer(oprfServer)
	if err != nil {
		panic(err)
	}

	// Two callisto clients
	callistoClientOne, err := client.NewCallistoClient(phatComputer)
	if err != nil {
		panic(err)
	}
	callistoClientTwo, err := client.NewCallistoClient(phatComputer)
	if err != nil {
		panic(err)
	}

	// Generate DLOC/LOC keys
	locKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}
	dlocKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}
	locPubKeys := client.LOCPublicKeys{
		LOCPublicKey:  locKeys.PublicKey,
		DLOCPublicKey: dlocKeys.PublicKey,
	}

	// Callisto entry
	entry := client.CallistoEntry{
		EntryData: types.EntryData{
			PerpetratorName:            "Foo",
			PerpetratorTwitterUserName: "@foo",
			VictimName:                 "Bar",
			VictimPhoneNumber:          "111-111-1111",
			VictimEmail:                "victim@email.com",
		},
		AssignmentData: types.AssignmentData{
			VictimStateOfCurrentResidence:    "AA",
			CategorizationOfSexualMisconduct: "Baz",
			IndustryOfPerpetrator:            "Z",
		},
	}

	// Compute two Callisto tuples of the same perp, but with two separate
	// users. Because two users have reported the same perp, LOCs/DLOCs can
	// decrypt
	perpID := []byte("perpID")
	tupleOne, err := callistoClientOne.CreateCallistoTuple(perpID, entry, locPubKeys)
	if err != nil {
		panic(err)
	}
	// Change the data slightly for user 2's report
	entry.AssignmentData.VictimStateOfCurrentResidence = "BB"
	entry.EntryData.PerpetratorTwitterUserName = "@bar"
	tupleTwo, err := callistoClientTwo.CreateCallistoTuple(perpID, entry, locPubKeys)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", tupleOne)
	fmt.Printf("%+v\n", tupleTwo)

	// Sanity check pi values are the same
	tuples := []protocol.HasPi{tupleOne, tupleTwo}
	matches, err := protocol.FindMatches(tuples)
	if err != nil {
		panic(err)
	}
	if len(matches) != 1 {
		panic("no matches were found")
	}
	if len(matches[0].MatchedEntries) != 2 {
		panic("incorrect length for matched tuples")
	}
	if !bytes.Equal(matches[0].MatchedEntries[0].Pi(), matches[0].MatchedEntries[1].Pi()) {
		panic("pi values are not equal")
	}
	fmt.Printf("Matches: %+v\n", matches)

	dlocCiphertexts := [][]byte{tupleOne.DLOCCiphertext(), tupleTwo.DLOCCiphertext()}
	encryptedAssignmentData := []encryption.GCMCiphertext{tupleOne.EncryptedAssignmentData(), tupleTwo.EncryptedAssignmentData()}
	assignmentResults, err := protocol.DecryptAssignmentData(dlocCiphertexts, encryptedAssignmentData, dlocKeys.PrivateKey)
	if err != nil {
		panic(err)
	}
	for _, d := range assignmentResults {
		fmt.Printf("%+v\n", d)
	}

	locCiphertexts := [][]byte{tupleOne.LOCCiphertext(), tupleTwo.LOCCiphertext()}
	encryptedEntryData := []encryption.GCMCiphertext{tupleOne.EncryptedEntryData(), tupleTwo.EncryptedEntryData()}
	entryResults, err := protocol.DecryptEntryData(locCiphertexts, encryptedEntryData, locKeys.PrivateKey)
	if err != nil {
		panic(err)
	}
	for _, d := range entryResults {
		fmt.Printf("%+v\n", d)
	}
}
