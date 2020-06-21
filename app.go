package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/outputter"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

func app(cmd *cobra.Command, args []string) {
	glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", cfgFile))
	_, err := os.Stat(cfgFile)
	if err != nil {
		glog.V(2).Info(fmt.Sprintf("config file: %s not found.\n", cfgFile))
		util.ExitWithError(err)
	}

	Main(cfgFile, define)
}

// Main entry point for benchmark functionality
func Main(filePath string, constraints []string) {
	controls, err := getControls(filePath, constraints, substitutionFile)
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
	format := outputter.ConsoleFormat
	if jsonFmt {
		format = outputter.JSONFormat
	}

	config := &outputter.Config{
		Console: outputter.Console{
			NoRemediations:    noRemediations,
			IncludeTestOutput: includeTestOutput,
		},
		Format:   format,
		Filename: outputFile,
	}

	o := outputter.BuildOutputter(summary, config)

	return o.Output(controls, summary)
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

func getControls(path string, constraints []string, substitutionFile string) (*check.Controls, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	substituMap := util.GetSubstitutionMap(substitutionFile)
	fmt.Printf("map: %v", substituMap)
	s := string(data)
	s = util.MakeSubstitutions(s, "", substituMap)
	controls, err := check.NewControls([]byte(s), constraints)
	if err != nil {
		return nil, err
	}

	return controls, err
}
