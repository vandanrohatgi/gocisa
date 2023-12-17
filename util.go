package gocisa

import (
	"os"
	"strings"
)

const (
	testData = "test/sample_response.json"
)

// Ptr helps to get the address of fields to create test data
func Ptr[K int | string](v K) *K {
	return &v
}

// Contains searches for a substring after converting the input to a lower case
// first
func Contains(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}

func readTestData() []byte {
	f, _ := os.ReadFile(testData)
	return f
}
