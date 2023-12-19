package main

import (
	"log"

	"github.com/vandanrohatgi/gocisa"
)

var fileName = "cisa-kev"
var extension = ".json"

func main() {
	fileName += extension
	client := gocisa.GetNewClient()
	err := client.FetchCatalogue()
	if err != nil {
		log.Fatalf("error fetching KEV catalogue: %v", err)
	}
	err = client.DumpCatalogue(fileName)
	if err != nil {
		log.Fatalf("error creating %s: %v", fileName, err)
	}
}
