// Copyright © 2019 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner

import (
	"archive/tar"
	"errors"
	"fmt"
	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
)

type BenchRunner struct {
	mConfigYaml []byte

	//optional
	mDefinitions []string

	//this file used in FileSearch directive,
	// instead walking thru real FS
	mTarHeaders []tar.Header

	//This directive is used by FileSearch and
	//TextSearch to restrict search folder boundary
	//i.e. only files in this folder are candidates for lookup
	mPathBoundary string

	//This variable used to determine either to run the shell command
	//in yaml 'audit' (i.e. shell cmd)  or 'action' attributes
	mIsActionTest bool

	mControls *check.Controls

	mCheckList string
}

func New(configYaml []byte) (runner *BenchRunner) {

	r := new(BenchRunner)
	r.mConfigYaml = configYaml
	return r
}

func (r *BenchRunner) WithConstrains(constrains []string) *BenchRunner {
	r.mDefinitions = constrains
	return r
}

func (r *BenchRunner) WithTarHeaders(tarHeaders []tar.Header) *BenchRunner {
	r.mTarHeaders = tarHeaders
	return r
}

func (r *BenchRunner) WithWorkSpace(pathBoundary string) *BenchRunner {
	r.mPathBoundary = pathBoundary
	return r
}

func (r *BenchRunner) WithAction(isAction bool) *BenchRunner {
	r.mIsActionTest = isAction
	return r
}

func (r *BenchRunner) WithCheckList(checkList string) *BenchRunner {
	r.mCheckList = checkList
	return r
}
func (r *BenchRunner) Build() (*BenchRunner, error) {
	// validate
	if r.mConfigYaml == nil {
		return nil, errors.New("ERROR empty yaml")
	}

	// try to parse the file and get controls
	var err error
	err = r.createControls()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *BenchRunner) createControls() (err error) {
	r.mControls, err = check.NewControls(r.mConfigYaml).WithIsAction(r.mIsActionTest).
		WithBoundary(r.mPathBoundary).
		WithDefinitions(r.mDefinitions).
		WithIds(util.CleanIDs(r.mCheckList)...).
		WithTarHeaders(r.mTarHeaders).
		Build()
	return err
}

func (r *BenchRunner) runTests() check.Summary {
	var summary check.Summary
	if r.mCheckList != "" {
		summary = r.mControls.RunChecks()
	} else {
		summary = r.mControls.RunGroup()
	}

	return summary
}

func (r *BenchRunner) RunTests() (*check.Controls, check.Summary, error) {
	summary := r.runTests()
	return  r.mControls, summary, nil
}

func (r *BenchRunner) RunTestsJson() (string, check.Summary, error) {
	summary := r.runTests()
	out, err := r.mControls.JSON()
	if err != nil {
		return "", summary, err
	}
	return string(out), summary, nil
}

// execute the test and print the result to stdin
func (r *BenchRunner) RunTestsWithOutput(jsonFmt bool, outputFile string, noRemediations bool, includeTestOutput bool) error {
	summary := r.runTests()
	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && jsonFmt {
		out, err := r.mControls.JSON()
		if err != nil {
			return err
		}
		util.PrintOutput(string(out), outputFile)

		} else {
		PrettyPrint(r.mControls, summary, noRemediations, includeTestOutput)
	}
	return nil
}

// prettyPrint outputs the results to stdout in human-readable format
func PrettyPrint(r *check.Controls, summary check.Summary, noRemediations, includeTestOutput bool) {
	util.ColorPrint(util.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Description))
	for _, g := range r.Groups {
		util.ColorPrint(util.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Description))
		for _, c := range g.Checks {
			util.ColorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Description))

			if includeTestOutput && c.State == util.FAIL && len(c.ActualValue) > 0 {
				util.PrintRawOutput(c.ActualValue)
			}
		}
	}

	fmt.Println()

	// Print remediations.
	if !noRemediations && (summary.Fail > 0 || summary.Warn > 0 || summary.Info > 0) {
		util.Colors[util.WARN].Printf("== Remediations ==\n")
		for _, g := range r.Groups {
			for _, c := range g.Checks {
				if c.State != util.PASS {
					fmt.Printf("%s %s\n", c.ID, c.Remediation)
				}
			}
		}
		fmt.Println()
	}

	// Print summary setting output color to highest severity.
	var res util.State
	if summary.Fail > 0 {
		res = util.FAIL
	} else if summary.Warn > 0 {
		res = util.WARN
	} else if summary.Info > 0 {
		res = util.INFO
	} else {
		res = util.PASS
	}

	util.Colors[res].Printf("== Summary ==\n")
	fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n%d checks INFO\n",
		summary.Pass, summary.Fail, summary.Warn, summary.Info,
	)
}