package gocisa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lithammer/fuzzysearch/fuzzy"
)

const (
	BaseURL    = "https://www.cisa.gov"
	KEVFeedURL = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	KEVCSVURL  = "/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)

// KEV represents the Known Exploited Vulnerabilities from CISA (CyberSecurity
// & Infrastructure Security Agency)
type KEV struct {
	BaseURL   string
	Client    *http.Client
	Catalogue *Catalogue
}

// Catalogue represents the threat activity data retrieved from CISA.
type Catalogue struct {
	Title           *string            `json:"title,omitempty"`
	CatalogVersion  *string            `json:"catalogVersion,omitempty"`
	DateReleased    *time.Time         `json:"dateReleased,omitempty"`
	Count           *int               `json:"count,omitempty"`
	Vulnerabilities []*Vulnerabilities `json:"vulnerabilities,omitempty"`
}

// Vulnerabilities represent the vulnerabilty data present in the KEV catalogue
type Vulnerabilities struct {
	CveID                      *string `json:"cveID,omitempty"`
	VendorProject              *string `json:"vendorProject,omitempty"`
	Product                    *string `json:"product,omitempty"`
	VulnerabilityName          *string `json:"vulnerabilityName,omitempty"`
	DateAdded                  *string `json:"dateAdded,omitempty"`
	ShortDescription           *string `json:"shortDescription,omitempty"`
	RequiredAction             *string `json:"requiredAction,omitempty"`
	DueDate                    *string `json:"dueDate,omitempty"`
	KnownRansomwareCampaignUse *string `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      *string `json:"notes,omitempty"`
}

// GetNewClient returns a new client with default values
func GetNewClient() *KEV {
	return &KEV{
		BaseURL: BaseURL,
		Client:  http.DefaultClient,
	}
}

// FetchCatalogue reaches out to cisa.gov, stores the records and returns an
// error if anything goes wrong.
func (k *KEV) FetchCatalogue() error {
	r, err := http.NewRequest(http.MethodGet, k.BaseURL+KEVFeedURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	response, err := k.Client.Do(r)
	if err != nil {
		return fmt.Errorf("error making request to %s: %w", KEVFeedURL, err)
	}
	defer response.Body.Close()

	err = json.NewDecoder(response.Body).Decode(&k.Catalogue)
	if err != nil {
		return fmt.Errorf("error decoding JSON response: %w", err)
	}
	return nil
}

// DumpCatalogue creates a JSON file of the KEV catalogue
func (k *KEV) DumpCatalogue(fileName string) error {
	if filepath.Ext(fileName) == "" {
		fileName += ".json"
	}
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer f.Close()
	byteData, err := json.MarshalIndent(k.Catalogue, " ", "  ")
	if err != nil {
		return fmt.Errorf("error creating JSON object: %w", err)
	}
	_, err = f.Write(byteData)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

// LookupProduct performs a fuzzy search across the whole vulnerability
// catalogue to find items for a specific product
func (k *KEV) LookupProduct(product string, fuzzySearch bool) []*Vulnerabilities {
	var results []*Vulnerabilities

	if fuzzySearch {
		for _, vuln := range k.Catalogue.Vulnerabilities {
			if fuzzy.MatchFold(product, *vuln.Product) {
				results = append(results, vuln)
			}
		}
	} else {
		for _, vuln := range k.Catalogue.Vulnerabilities {
			if Contains(*vuln.Product, product) {
				results = append(results, vuln)
			}
		}
	}
	return results
}
