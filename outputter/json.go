package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type JSON struct{}

const JSONFilenameKey = "JSONFilenameKey"

func (jrp *JSON) Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	if len(maybeConfig) == 0 {
		return fmt.Errorf("JSON - Config parameters are required")
	}
	config := maybeConfig[0]
	outputFile, found := config[JSONFilenameKey]
	if !found {
		return fmt.Errorf("JSON - Config parameter missing - %s", JSONFilenameKey)
	}

	out, err := controls.JSON()
	if err != nil {
		return err
	}

	err = OutputToFile(string(out), outputFile)
	if err != nil {
		return err
	}
	return nil
}
