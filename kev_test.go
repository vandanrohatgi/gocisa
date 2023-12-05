package gocisa_test

import (
	"net/http"
	"testing"

	"github.com/vandanrohatgi/gocisa"
)

func Test_fetchCatalogue(t *testing.T) {
	var k = gocisa.KEV{
		Client: http.DefaultClient,
	}

	err := k.FetchCatalogue()
	if err != nil {
		t.Fatal(err)
	}
}
