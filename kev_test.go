package gocisa

import (
	"errors"
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

	if len(k.Catalogue.Vulnerabilities) != *k.Catalogue.Count {
		t.Fatalf("expected %d records, found %d", *k.Catalogue.Count, len(k.Catalogue.Vulnerabilities))
	}

}

func Test_dumpCatalogue(t *testing.T) {
	tmpDir := os.TempDir()
	fileName := tmpDir + "/cisa_kev.json"

	k := &KEV{
		Catalogue: &Catalogue{
			Title: Ptr[string]("test title"),
			Count: Ptr[int](1),
			Vulnerabilities: []*Vulnerabilities{
				{
					CveID: Ptr[string]("CVE-1234-5678"),
				},
			},
		},
	}

	err := k.DumpCatalogue(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fileName)

	if _, err := os.Stat(fileName); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file %s does not exist: %v", fileName, err)
	}
}
