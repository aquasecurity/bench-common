package main

import (
	"fmt"
	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

func app(cmd *cobra.Command, args []string) {
	err := checkDefinitionFilePath(cfgFile)
	if err != nil {
		util.ExitWithError(err)
	}

	Main(cfgFile, define)
}

func Main(filePath string, constraints []string) {
	controls, err := getControls(filePath, constraints)
	if err != nil {
		util.ExitWithError(err)
	}

	summary := runControls(controls, "")
	err = outputResults(controls, summary)
	if err != nil {
		util.ExitWithError(err)
	}
}

func outputResults(controls *check.Controls, summary check.Summary) error {
	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			return err
		}
		util.PrintOutput(string(out), outputFile)
	} else {
		util.PrettyPrint(controls, summary, noRemediations, includeTestOutput)
	}

	return nil
}

func runControls(controls *check.Controls, checkList string) check.Summary {
	var summary check.Summary

	if checkList != "" {
		ids := util.CleanIDs(checkList)
		summary = controls.RunChecks(ids...)
	} else {
		summary = controls.RunGroup()
	}

	return summary
}

func getControls(path string, constraints []string) (*check.Controls, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	controls, err := check.NewControls([]byte(data), constraints)
	if err != nil {
		return nil, err
	}

	return controls, err
}

func checkDefinitionFilePath(filePath string) (err error) {
	glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", filePath))
	_, err = os.Stat(filePath)

	return err
}
