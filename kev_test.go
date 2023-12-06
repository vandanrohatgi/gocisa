package gocisa

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Test_fetchCatalogue(t *testing.T) {
	testMux := http.NewServeMux()

	testMux.HandleFunc(KEVFeedURL, func(w http.ResponseWriter, _ *http.Request) {
		f, err := os.ReadFile("test/sample_response.json")
		if err != nil {
			t.Fatalf("error reading test data: %v", err)
		}

		_, err = w.Write(f)
		if err != nil {
			t.Fatalf("error writing response: %v", err)
		}
	})

	testServ := httptest.NewServer(testMux)
	defer testServ.Close()

	var k = KEV{
		Client:  testServ.Client(),
		BaseURL: testServ.URL,
	}

	err := k.FetchCatalogue()
	if err != nil {
		t.Fatal(err)
	}

	if len(k.Catalogue.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 records, found %d", len(k.Catalogue.Vulnerabilities))
	}
}
