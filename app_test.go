package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

func init() {
	jsonFmt = true
}

// Check that JSON format output creates valid JSON
func TestOutputResults(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	outputFile = tmpfile.Name()

	// TODO: JSON output summary currently requires at least one test result to generate output
	summary := check.Summary{Pass: 1}
	controls := check.Controls{
		Groups: []*check.Group{{
			ID: "ID",
			Checks: []*check.Check{{
				ID:   "CheckID",
				Type: "skip",
			}},
		}},
	}

	err = outputResults(&controls, summary)
	if err != nil {
		t.Fatalf("outputResults failed: %v", err)
	}

	output, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !json.Valid(output) {
		t.Fatalf("JSON output invalid")
	}
}
