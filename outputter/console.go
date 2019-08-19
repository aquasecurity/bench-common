package outputter

import (
	"fmt"
	"strconv"

	"github.com/golang/glog"

	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
)

type Console struct{}

const NoRemediationsKey = "NoRemediationsKey"
const IncludeTestOutputKey = "IncludeTestOutputKey"

func (co *Console) Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	if len(maybeConfig) == 0 {
		return fmt.Errorf("Console - Config parameters are required\n")
	}
	config := maybeConfig[0]

	noRemediations := false
	noRemediationsStr, found := config[NoRemediationsKey]
	if found {
		if b, err := strconv.ParseBool(noRemediationsStr); err == nil {
			noRemediations = b
		} else {
			glog.V(2).Info(fmt.Sprintf("Console - Unable to convert %q to boolean\n", noRemediationsStr))
		}
	}

	includeTestOutput := false
	includeTestOutputStr, found := config[IncludeTestOutputKey]
	if !found {
		if b, err := strconv.ParseBool(includeTestOutputStr); err == nil {
			noRemediations = b
		} else {
			glog.V(2).Info(fmt.Sprintf("Console - Unable to convert %q to boolean\n", includeTestOutputStr))
		}
	}

	util.PrettyPrint(controls, summary, noRemediations, includeTestOutput)
	return nil
}
