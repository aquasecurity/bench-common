package outputter

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

type mockFile struct {
	fail bool
}

func (mf *mockFile) Handle(data string) error {
	if mf.fail {
		return fmt.Errorf("Failed to Handle data")
	}
	return nil
}

type mockConverter struct {
	fail bool
}

var errorTestFailedToConvert = fmt.Errorf("Failed to ConvertToJSON data")

func (cj *mockConverter) ConvertToJSON(controls *check.Controls) ([]byte, error) {
	if cj.fail {
		return nil, errorTestFailedToConvert
	}
	return nil, nil
}

func TestOutput(t *testing.T) {
	cases := []struct {
		n             string
		json          *JSON
		expectedError error
		fail          bool
		controls      *check.Controls
	}{
		{
			n:             "errFileHandlerRequired",
			json:          &JSON{},
			expectedError: errFileHandlerRequired,
			controls:      &check.Controls{},
		},
		{
			n: "fileHandlerProvidedFailed",
			json: &JSON{
				FileHandler: &mockFile{
					fail: false,
				},
			},
			fail: true,
		},
		{
			n: "fileHandlerProvidedPass",
			json: &JSON{
				FileHandler: &mockFile{
					fail: false,
				},
			},
			expectedError: errMissingControls,
		},
	}
	summary := check.Summary{}

	for _, c := range cases {
		err := c.json.Output(c.controls, summary)
		if c.expectedError != nil {
			if c.expectedError != err {
				t.Errorf("Expected Error %q but got %q", c.expectedError, err)
			}
		} else if c.fail {
			if err == nil {
				t.Errorf("%s - Expected Error to be returned", c.n)
			}
		} else if err != nil {
			t.Fatalf("%s - Unexpected Test Error: %v", c.n, err)
		}
	}
}
