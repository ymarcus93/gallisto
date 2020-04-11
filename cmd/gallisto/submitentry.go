package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/ymarcus93/gallisto/protocol/client"
	"github.com/ymarcus93/gallisto/types"
)

func submitEntry() error {
	// User picks which client to use
	err := clientSelection()
	if err != nil {
		return err
	}

	// User inputs data for submission
	dataInput, err := dataInput()
	if err != nil {
		return err
	}
	callistoEntry := convertDataInputToCallistoEntry(dataInput)

	// Create the Callisto tuple
	perpID := []byte(callistoEntry.EntryData.PerpetratorName)
	locPubKeys := client.LOCPublicKeys{
		LOCPublicKey:  pubkeys.locKeys.PublicKey,
		DLOCPublicKey: pubkeys.dlocKeys.PublicKey,
	}
	callistoTuple, err := currClient.CreateCallistoTuple(perpID, callistoEntry, locPubKeys)
	if err != nil {
		panic(err)
	}
	callistoTuples = append(callistoTuples, callistoTuple)
	println("successfully submitted an entry!")
	return nil
}

func clientSelection() error {
	// Create a new client if none are available
	if len(callistoClients) == 0 {
		fmt.Println("creating initial callisto client")
		newClient, err := createCallistoClient(oprfServer)
		if err != nil {
			return fmt.Errorf("failed to create initial callisto client: %v", err)
		}
		addCallistoClient(newClient)
		currClient = newClient
	} else {
		// Otherwise ask the user if he wants to create a new client or pick a
		// specific client to use
		askToMakeMoreMsg := fmt.Sprintf("There are already %v client(s). Do you want to create another one? (default: No)", len(callistoClients))
		var createAnotherOne bool
		prompt := &survey.Confirm{
			Message: askToMakeMoreMsg,
			Default: false,
		}
		promptErr := survey.AskOne(prompt, &createAnotherOne)
		if promptErr != nil {
			return promptErr
		}

		if createAnotherOne {
			newClient, err := createCallistoClient(oprfServer)
			if err != nil {
				return fmt.Errorf("failed to create initial callisto client: %v", err)
			}
			addCallistoClient(newClient)
			currClient = newClient
		} else {
			// Don't prompt client selection if there is only one available
			if len(callistoClients) == 1 {
				return nil
			}
			err := askWhichClientToUse()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func dataInput() (dataInputAnswers, error) {
	var dataInputQuestions = []*survey.Question{
		{
			Name: "PerpetratorName",
			Prompt: &survey.Input{
				Message: "What is the perpetrator's name?",
				Default: "Foo",
			},
			Transform: survey.Title,
		},
		{
			Name: "PerpetratorTwitterUserName",
			Prompt: &survey.Input{
				Message: "What is the perpetrator's twitter user name?",
				Default: "foo",
			},
			Transform: survey.TransformString(prependAmpersand),
		},
		{
			Name: "VictimName",
			Prompt: &survey.Input{
				Message: "What is the victim's name?",
				Default: "Bar",
			},
			Transform: survey.Title,
		},
		{
			Name: "VictimPhoneNumber",
			Prompt: &survey.Input{
				Message: "What is the victim's phone number?",
				Default: "111-234-5678",
			},
		},
		{
			Name: "VictimEmail",
			Prompt: &survey.Input{
				Message: "What is the victim's email?",
				Default: "bar@mail.com",
			},
		},
		{
			Name: "VictimStateOfCurrentResidence",
			Prompt: &survey.Select{
				Message: "What is the victim's current state of residence?",
				Options: usStates,
				Default: "Massachusetts",
			},
		},
		{
			Name: "CategorizationOfSexualMisconduct",
			Prompt: &survey.MultiSelect{
				Message: "Which categorie(s) of sexual misconduct does this incident fit?",
				Options: categories,
			},
		},
		{
			Name: "IndustryOfPerpetrator",
			Prompt: &survey.Input{
				Message: "What is the perpetrator's industry?",
				Default: "Foo industry",
			},
		},
	}

	// Perform the questions
	var input dataInputAnswers
	err := survey.Ask(dataInputQuestions, &input)
	if err != nil {
		return dataInputAnswers{}, err
	}
	return input, nil
}

type dataInputAnswers struct {
	PerpetratorName                  string
	PerpetratorTwitterUserName       string
	VictimName                       string
	VictimPhoneNumber                string
	VictimEmail                      string
	VictimStateOfCurrentResidence    string
	CategorizationOfSexualMisconduct []string
	IndustryOfPerpetrator            string
}

func convertDataInputToCallistoEntry(input dataInputAnswers) client.CallistoEntry {
	return client.CallistoEntry{
		EntryData: types.EntryData{
			PerpetratorName:            input.PerpetratorName,
			PerpetratorTwitterUserName: input.PerpetratorTwitterUserName,
			VictimName:                 input.VictimName,
			VictimPhoneNumber:          input.VictimPhoneNumber,
			VictimEmail:                input.VictimEmail,
		},
		AssignmentData: types.AssignmentData{
			VictimStateOfCurrentResidence:    input.VictimStateOfCurrentResidence,
			CategorizationOfSexualMisconduct: strings.Join(input.CategorizationOfSexualMisconduct[:], ","),
			IndustryOfPerpetrator:            input.IndustryOfPerpetrator,
		},
	}
}

func addCallistoClient(client *client.CallistoClient) {
	name := strconv.Itoa(len(callistoClients) + 1)
	callistoClients[name] = client
}

func getListOfCallistoClientIDs() []string {
	clientIDs := make([]string, 0, len(callistoClients))
	for k := range callistoClients {
		clientIDs = append(clientIDs, k)
	}
	return clientIDs
}

func askWhichClientToUse() error {
	listOfClients := getListOfCallistoClientIDs()
	clientSelectionPrompt := &survey.Select{
		Message: "Ok. Then which client should we use?:",
		Options: listOfClients,
		Default: listOfClients[0],
	}
	var clientToUse string
	promptError := survey.AskOne(clientSelectionPrompt, &clientToUse)
	if promptError != nil {
		return promptError
	}
	currClient = callistoClients[clientToUse]
	return nil
}
