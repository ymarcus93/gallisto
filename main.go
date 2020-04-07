package main

import (
	"fmt"

	"github.com/ymarcus93/gallisto/callisto"
	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/oprf"
	"github.com/ymarcus93/gallisto/types"
)

func main() {
	callistoClient, err := callisto.NewCallistoClient(types.OPRF_CIPHERSUITE)
	if err != nil {
		panic(err)
	}

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

	locKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}
	dlocKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}

	locPubKeys := types.LOCPublicKeys{
		LOCPublicKey:  locKeys.PublicKey,
		DLOCPublicKey: dlocKeys.PublicKey,
	}

	entry := types.CallistoEntry{
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

	perpID := []byte("perpID")
	tuple, err := callistoClient.CreateCallistoTuple(perpID, entry, locPubKeys, oprfServer)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", tuple)
}
