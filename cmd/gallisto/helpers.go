package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/oprf"
	"github.com/ymarcus93/gallisto/protocol/client"
	"github.com/ymarcus93/gallisto/types"
)

func createOPRFServer() (*oprf.OPRFServer, error) {
	fmt.Println("generating OPRF key...")
	key, err := oprf.GenerateKey(types.OPRF_CIPHERSUITE)
	if err != nil {
		return nil, err
	}
	fmt.Println("creating OPRF server...")
	oprfServer, err := oprf.NewOPRFServer(types.OPRF_CIPHERSUITE, key)
	if err != nil {
		return nil, err
	}
	return oprfServer, nil
}

func createCallistoClient(oprfEvaluator oprf.OPRFEvaluator) (*client.CallistoClient, error) {
	pHatComputer, err := oprf.NewPHatComputer(oprfEvaluator)
	if err != nil {
		return nil, err
	}
	callistoClient, err := client.NewCallistoClient(pHatComputer)
	if err != nil {
		return nil, err
	}
	return callistoClient, nil
}

type locAndDLOCKeys struct {
	locKeys  encryption.RSAKeyPair
	dlocKeys encryption.RSAKeyPair
}

func createLOCAndDLOCKeys() (locAndDLOCKeys, error) {
	fmt.Println("creating LOC/DLOC keys...")
	locKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		return locAndDLOCKeys{}, fmt.Errorf("failed to craeate loc keys: %v", err)
	}
	dlocKeys, err := encryption.GenerateRSAKeyPair()
	if err != nil {
		return locAndDLOCKeys{}, fmt.Errorf("failed to craeate dloc keys: %v", err)
	}
	return locAndDLOCKeys{locKeys: locKeys, dlocKeys: dlocKeys}, nil
}

func handleError(err error) {
	// All errors lead to exit
	if err == terminal.InterruptErr {
		fmt.Println("Caught interrupt. Exiting...")
		os.Exit(0)
	}
	if err != nil {
		// Print error
		fmt.Println("\ngot error:")
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func prependAmpersand(s string) string {
	return "@" + s
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
