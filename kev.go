package gocisa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	BaseURL    = "https://www.cisa.gov/sites/default/files"
	KEVFeedURL = "/feeds/known_exploited_vulnerabilities.json"
	KEVCSVURL  = "/csv/known_exploited_vulnerabilities.csv"
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
	err = json.NewDecoder(response.Body).Decode(&k.Catalogue)
	if err != nil {
		return fmt.Errorf("error decoding JSON response: %w", err)
	}
	return nil
}
