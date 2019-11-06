package outputter

import (
	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
)

// Console outputter functionality for Standard output
type Console struct {
	NoRemediations    bool
	IncludeTestOutput bool
}

// NewConsole creates new Outputter of type Console
func NewConsole(noRemediations, includeTestOutput bool) *Console {
	return &Console{
		NoRemediations:    noRemediations,
		IncludeTestOutput: includeTestOutput,
	}
}

// Output displays Control results to Standard output
func (co *Console) Output(controls *check.Controls, summary check.Summary) error {
	util.PrettyPrint(controls, summary, co.NoRemediations, co.IncludeTestOutput)
	return nil
}
