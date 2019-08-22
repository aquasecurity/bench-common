package outputter

import (
	"bytes"
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
		json          *JSON
		expectedError error
		fail          bool
		controls      *check.Controls
	}{
		{
			json:          &JSON{},
			expectedError: ErrFileHandlerRequired,
			controls:      &check.Controls{},
		},
		{
			json: &JSON{
				FileHandler: &mockFile{},
			},
			expectedError: ErrConverterRequired,
			controls:      &check.Controls{},
		},
		{
			json: &JSON{
				FileHandler: &mockFile{
					fail: false,
				},
				Converter: &mockConverter{
					fail: true,
				},
			},
			fail:     true,
			controls: &check.Controls{},
		},
		{
			json: &JSON{
				FileHandler: &mockFile{
					fail: false,
				},
				Converter: &JSONDelegate{},
			},
			expectedError: ErrMissingControls,
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
				t.Errorf("Expected Error to be returned")
			}
		} else if err != nil {
			t.Fatalf("Unexpected Test Error: %v", err)
		}
	}
}

func TestConvertToJSON(t *testing.T) {
	jd := &JSONDelegate{}
	_, err := jd.ConvertToJSON(nil)
	if err == nil {
		t.Errorf("Expected Error %q but got %q", ErrMissingControls, err)
	}

	jd = &JSONDelegate{}
	controls := &check.Controls{
		ID:          "12121",
		Description: "testControl",
	}
	d, err := jd.ConvertToJSON(controls)
	if err != nil {
		t.Errorf("Expected Error %q but got %q", ErrMissingControls, err)
	}

	expectedOutput := []byte(`{"id":"12121","text":"testControl","tests":null,"total_pass":0,"total_fail":0,"total_warn":0,"total_info":0,"DefinedConstraints":null}`)
	if !bytes.Equal(expectedOutput, d) {
		t.Errorf("%q != %q ", expectedOutput, d)
	}
}
