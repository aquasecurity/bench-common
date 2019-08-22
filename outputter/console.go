package outputter

import (
	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
)

type Console struct {
	NoRemediations    bool
	IncludeTestOutput bool
}

func (co *Console) Output(controls *check.Controls, summary check.Summary) error {
	util.PrettyPrint(controls, summary, co.NoRemediations, co.IncludeTestOutput)
	return nil
}
