package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type Outputter interface {
	Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error
}

func OutputResults(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	
	o := determineOutputter(controls, summary)
	return o.Output(controls, summary, maybeConfig...)
}

func determineOutputter(controls *check.Controls, summary check.Summary) *Outputter {
	if summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0 {
		return &JSON{}
	} else {
		return &Console{}
	}
}

func getFirstConfig(maybeConfig ...map[string]string) (map[string]string, error) {
	if len(maybeConfig) == 0 {
		return nil, fmt.Errorf("Config parameters are required")
	}
	return maybeConfig[0], nil
}

func getMapValue(k string, m map[string]string) (string, error) {
	retVal, found := m[k]
	if !found {
		return "", fmt.Errorf("Map does not contain %q", k))
	}
	return retVal, nil
}