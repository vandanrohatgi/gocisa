package gocisa

import (
	"time"
)

const (
	kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevCSVURL  = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)

type Catalogue struct {
	Title           string            `json:"title,omitempty"`
	CatalogVersion  string            `json:"catalogVersion,omitempty"`
	DateReleased    time.Time         `json:"dateReleased,omitempty"`
	Count           int               `json:"count,omitempty"`
	Vulnerabilities []Vulnerabilities `json:"vulnerabilities,omitempty"`
}

type Vulnerabilities struct {
	CveID                      string `json:"cveID,omitempty"`
	VendorProject              string `json:"vendorProject,omitempty"`
	Product                    string `json:"product,omitempty"`
	VulnerabilityName          string `json:"vulnerabilityName,omitempty"`
	DateAdded                  string `json:"dateAdded,omitempty"`
	ShortDescription           string `json:"shortDescription,omitempty"`
	RequiredAction             string `json:"requiredAction,omitempty"`
	DueDate                    string `json:"dueDate,omitempty"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string `json:"notes,omitempty"`
}
