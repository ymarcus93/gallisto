package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ymarcus93/gallisto/internal/oprf"
	"github.com/ymarcus93/gallisto/protocol/client"
	"github.com/ymarcus93/gallisto/types"

	"github.com/AlecAivazis/survey/v2"
)

// Global state
var oprfServer *oprf.OPRFServer
var pubkeys locAndDLOCKeys

var currClient *client.CallistoClient
var callistoClients = make(map[string]*client.CallistoClient)
var callistoTuples = make([]types.CallistoTuple, 0)

func main() {
	SetupCloseHandler()
	var err error

	// We always start off with a new OPRF server
	oprfServer, err = createOPRFServer()
	handleError(err)

	// and some DLOC/LOC key generation
	pubkeys, err = createLOCAndDLOCKeys()
	handleError(err)

	println("\ninitial setup complete!")

	mainMenuPrompt := &survey.Select{
		Message: "Choose an action:",
		Options: []string{"Submit entry", "Find matches", "Exit"},
	}
	for {
		var action string
		promptError := survey.AskOne(mainMenuPrompt, &action)
		handleError(promptError)

		switch action {
		case "Submit entry":
			err = submitEntry()
		case "Find matches":
			err = findMatches()
		case "Exit":
			exit()
		}

		handleError(err)
		fmt.Println("\nCompleted action:", action)
	}
}

func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println(" Caught interrupt. Exiting...")
		os.Exit(0)
	}()
}

func exit() {
	fmt.Println("Bye!")
	os.Exit(0)
}
