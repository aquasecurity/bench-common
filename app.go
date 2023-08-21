package main

import (
	"io/ioutil"
	"os"

	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/outputter"
	"github.com/aquasecurity/bench-common/util"
	"github.com/spf13/cobra"
)

func app(cmd *cobra.Command, args []string) {
	_, err := os.Stat(cfgFile)
	if err != nil {
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
	normalizeOutputStruct(controls)
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
	s := string(data)
	if substitutionFile != "" {
		substitutionData, err := ioutil.ReadFile(substitutionFile)
		if err != nil {
			return nil, err
		}
		substituMap, err := util.GetSubstitutionMap(substitutionData)
		if err != nil {
			return nil, err
		}
		s = util.MakeSubstitutions(s, "", substituMap)
	}
	controls, err := check.NewControls([]byte(s), constraints)
	if err != nil {
		return nil, err
	}

	return controls, err
}

func normalizeOutputStruct(controls *check.Controls) {
	/* There are two ways to set the description of a control: via controls.Description or via controls.Text
	   If controls.Description is empty, then the description is set via control.Text - controls.Description has priority.
	   Docker-bench CIS (docker-bench) will set controls.Description, and K8s CIS (kube-bench) will set controls.Text. The same applies to groups and checks.
	   Kube-Bench: https://github.com/aquasecurity/kube-bench/blob/main/cfg/cis-1.20/master.yaml#L5
	   Docker-Bench: https://github.com/aquasecurity/docker-bench/blob/main/cfg/cis-1.3.1/definitions.yaml#L4
	   The output struct is normalized such that controls.Description is set in both cases (controls.Description and controls.Text).
	*/
	// Normalize control description
	if controls.Description == "" && controls.Text != "" {
		controls.Description = controls.Text
	}
	// Normalize group description
	for _, group := range controls.Groups {
		if group.Description == "" && group.Text != "" {
			group.Description = group.Text
		}
		// Normalize checks description
		for _, chk := range group.Checks {
			if chk.Description == "" && chk.Text != "" {
				chk.Description = chk.Text
			}
		}
	}
}
