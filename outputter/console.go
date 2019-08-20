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
	config, err := getFirstConfig(maybeConfig...)
	if err != nil {
		return fmt.Errorf("Console - %v", err)
	}

	noRemediations, err := getBool(NoRemediationsKey, config)
	if err != nil {
		glog.V(2).Info(fmt.Sprintf("Console - Unable to get %s from config: %v\n", NoRemediationsKey, err))
	} 

	includeTestOutput err := getBool(IncludeTestOutputKey, config)
	if err != nil {
		glog.V(2).Info(fmt.Sprintf("Console - Unable to get %s from config: %v\n", IncludeTestOutputKey, err))
	}

	util.PrettyPrint(controls, summary, noRemediations, includeTestOutput)
	return nil
}

func getBool(k string, m map[string]string) (bool, error) {
	retVal := false
	bs, err := getMapValue(k,m)
	if err != nil {
		return false, err
	}

	if b, err := strconv.ParseBool(bs); err == nil {
		retVal = b
	} else {
		return false, fmt.Errorf("Unable to convert %q to boolean", bs)
	}

	return false, retVal
}
