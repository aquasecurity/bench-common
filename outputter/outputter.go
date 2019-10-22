package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type Outputter interface {
	Output(controls *check.Controls, summary check.Summary) error
}

type OutputFunc func(controls *check.Controls, summary check.Summary) error

func (f OutputFunc) Output(controls *check.Controls, summary check.Summary) error {
	return f(controls, summary)
}

type Config struct {
	Console
	JSON
	JSONFormat bool
}

func BuildOutputter(controls *check.Controls, summary check.Summary, config *Config) Outputter {
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && config.JSONFormat {
		return NewJSON(config.JSON.Filename)
	}

	return NewConsole(config.Console.NoRemediations, config.Console.IncludeTestOutput)
}

func BuildOutputterFunc(op func(controls *check.Controls, summary check.Summary) error) (Outputter, error) {
	if op == nil {
		return nil, fmt.Errorf("BuildOutputterFunc: nil outputter")
	}

	return OutputFunc(op), nil
}
