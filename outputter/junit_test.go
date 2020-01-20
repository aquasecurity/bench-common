package outputter

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

type junitmockFile struct {
	fail bool
}

func (mf *junitmockFile) Handle(data string) error {
	if mf.fail {
		return fmt.Errorf("Failed to Handle data")
	}
	return nil
}

func TestOutputJUnit(t *testing.T) {
	cases := []struct {
		n             string
		junit         *JUnit
		expectedError error
		fail          bool
		controls      *check.Controls
	}{
		{
			n: "happy path",
			junit: &JUnit{
				fileHandler: &junitmockFile{fail: false},
			},
			controls: &check.Controls{},
		},
		{
			n:             "errFileHandlerRequired",
			junit:         &JUnit{},
			expectedError: errFileHandlerRequired,
			controls:      &check.Controls{},
		},
		{
			n: "fileHandlerProvidedFailed",
			junit: &JUnit{
				fileHandler: &junitmockFile{
					fail: false,
				},
			},
			fail: true,
		},
		{
			n: "fileHandlerProvidedPass",
			junit: &JUnit{
				fileHandler: &junitmockFile{
					fail: false,
				},
			},
			expectedError: errMissingControls,
		},
	}
	summary := check.Summary{}

	for _, c := range cases {
		err := c.junit.Output(c.controls, summary)
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
