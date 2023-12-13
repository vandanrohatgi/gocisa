package gocisa

import (
	"encoding/json"
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

func Test_lookupProduct(t *testing.T) {
	f, err := os.ReadFile("test/sample_response.json")
	if err != nil {
		t.Fatalf("error reading test data: %v", err)
	}
	var k KEV

	err = json.Unmarshal(f, &k.Catalogue)
	if err != nil {
		t.Fatal(err)
	}

	var tests = []struct {
		name  string
		input string
		fuzzy bool
		want  int
	}{
		{
			name:  "normal search",
			input: "fatcat",
			fuzzy: false,
			want:  1,
		},
		{
			name:  "normal fuzzy search",
			input: "fat",
			fuzzy: true,
			want:  1,
		},
		{
			name:  "no match normal search",
			input: "fakeProd",
			fuzzy: false,
			want:  0,
		},
		{
			name:  "no match fuzzy search",
			input: "fka",
			fuzzy: true,
			want:  0,
		},
	}

	for _, i := range tests {
		match := k.LookupProduct(i.input, i.fuzzy)
		if len(match) != i.want {
			t.Fatalf("%s expected %d, got: %d", i.name, i.want, len(match))
		}
	}
}
