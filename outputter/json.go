package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type JSON struct{}

const JSONFilenameKey = "JSONFilenameKey"

type Jsonner interface {
	JSON() ([]byte, error)
}

func (jrp *JSON) Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	config, err := getFirstConfig(maybeConfig...)
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	outputFile, err := getMapValue(JSONFilenameKey, config)
	if err != nil {
		return fmt.Errorf("JSON - Config parameter missing - %s", JSONFilenameKey)
	}

	out, err := convertToJSON(controls)
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	err = OutputToFile(string(out), outputFile)
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}
	return nil
}

func convertToJSON(j Jsonner) ([]byte, error) {
	return j.JSON()
}
