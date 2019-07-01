// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
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

package check

import (
	"archive/tar"
	"fmt"
	"github.com/aquasecurity/bench-common/actioneval"
	"github.com/aquasecurity/bench-common/auditeval"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
)

// State is the state of a control check.

type Action struct {
	CheckType string        `yaml:"type"`
	Args      yaml.MapSlice `yaml:"args"`
	Count     bool          `yaml:"count"`
}

// Old version - checks don't have sub checks, each check has only one sub check as part of the check itself
type BaseCheck struct {
	Audit       string              `json:"audit"`
	Action      Action              `json:"action" yaml:"action"`
	Type        string              `json:"type"`
	Commands    []*exec.Cmd         `json:"omit"`
	Tests       *auditeval.Tests    `json:"omit"`
	Remediation string              `json:"-"`
	Constraints map[string][]string `yaml:"constraints"`
}

type SubCheck struct {
	BaseCheck `yaml:"check"`
}

// Check contains information about a recommendation.
type Check struct {
	ID             string           `yaml:"id" json:"test_number"`
	Description    string           `json:"test_desc"`
	Set            bool             `json:"omit"`
	SubChecks      []SubCheck       `yaml:"sub_checks"`
	Audit          string           `json:"audit"`
	Type           string           `json:"type"`
	Action         Action           `json:"action" yaml:"action"`
	Commands       []*exec.Cmd      `json:"omit"`
	Tests          *auditeval.Tests `json:"omit"`
	Remediation    string           `json:"-"`
	TestInfo       []string         `json:"test_info"`
	util.State     `json:"status"`
	ActualValue    string `json:"actual_value"`
	ExpectedResult string `json:"expected_result"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`

	//Internal members
	boundaryPath string       `json:"-"`
	isAction     bool         `json:"-"`
	tarHeaders   []tar.Header `json:"-"`
}

// Group is a collection of similar checks.
type Group struct {
	ID          string   `yaml:"id" json:"section"`
	Description string   `json:"desc"`
	Checks      []*Check `json:"results"`
	Pass        int      `json:"pass"` // Tests with no type that passed
	Fail        int      `json:"fail"` // Tests with no type that failed
	Warn        int      `json:"warn"` // Tests of type manual won't be run and will be marked as Warn
	Info        int      `json:"info"` // Tests of type skip won't be run and will be marked as Info
}

func (c *Check) WithBoundaryPath(boundaryPath string) *Check {
	c.boundaryPath = boundaryPath
	return c
}

func (c *Check) WithAction(isAction bool) *Check {
	c.isAction = isAction
	return c
}

func (c *Check) WithTarHeaders(tarHeaders []tar.Header) *Check {
	c.tarHeaders = tarHeaders
	return c
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) Run(definedConstraints map[string][]string) {
	// If check type is skip, force result to INFO
	if c.Type == "skip" {
		c.State = util.INFO
		return
	}

	//If check type is manual or the check is not scored, force result to WARN
	if c.Type == "manual" || !c.Scored {
		c.State = util.WARN
		return
	}

	var subCheck *BaseCheck
	if c.SubChecks == nil {
		subCheck = &BaseCheck{
			Commands:    c.Commands,
			Tests:       c.Tests,
			Type:        c.Type,
			Audit:       c.Audit,
			Action:      c.Action,
			Remediation: c.Remediation,
		}
	} else {
		subCheck = getFirstValidSubCheck(c.SubChecks, definedConstraints)

		if subCheck == nil {
			c.State = util.WARN
			glog.V(1).Info("Failed to find a valid sub check, check ", c.ID)
			return
		}
	}

	var out, errmsgs string

	if !c.isAction {
		out, errmsgs, c.State = runAuditCommands(*subCheck)
	} else {

		out, errmsgs, c.State = c.runAction(*subCheck)
	}

	if errmsgs != "" {
		glog.V(2).Info(errmsgs)
	}

	if c.State != "" {
		return
	}

	finalOutput := subCheck.Tests.Execute(out, c.ID, c.IsMultiple)

	if finalOutput != nil {
		c.ActualValue = finalOutput.ActualResult
		c.ExpectedResult = finalOutput.ExpectedResult

		if finalOutput.TestResult {
			c.State = util.PASS
		} else {
			c.State = util.FAIL
		}
	} else {
		c.State = util.WARN
		glog.V(1).Info("Test output contains a nil value")
		return
	}
}

// textToCommand transforms an input text representation of commands to be
// run into a slice of commands.
// TODO: Make this more robust.
func textToCommand(s string) []*exec.Cmd {
	cmds := []*exec.Cmd{}

	cp := strings.Split(s, "|")

	for _, v := range cp {
		v = strings.Trim(v, " ")

		// TODO:
		// GOAL: To split input text into arguments for exec.Cmd.
		//
		// CHALLENGE: The input text may contain quoted strings that
		// must be passed as a unit to exec.Cmd.
		// eg. bash -c 'foo bar'
		// 'foo bar' must be passed as unit to exec.Cmd if not the command
		// will fail when it is executed.
		// eg. exec.Cmd("bash", "-c", "foo bar")
		//
		// PROBLEM: Current solution assumes the grouped string will always
		// be at the end of the input text.
		re := regexp.MustCompile(`^(.*)(['"].*['"])$`)
		grps := re.FindStringSubmatch(v)

		var cs []string
		if len(grps) > 0 {
			s := strings.Trim(grps[1], " ")
			cs = strings.Split(s, " ")

			s1 := grps[len(grps)-1]
			s1 = strings.Trim(s1, "'\"")

			cs = append(cs, s1)
		} else {
			cs = strings.Split(v, " ")
		}

		cmd := exec.Command(cs[0], cs[1:]...)
		cmds = append(cmds, cmd)
	}

	return cmds
}

func isShellCommand(s string) bool {
	cmd := exec.Command("/bin/sh", "-c", "command -v "+s)

	out, err := cmd.Output()
	if err != nil {
		return false
	}

	if strings.Contains(string(out), s) {
		return true
	}
	return false
}

func runAuditCommands(c BaseCheck) (output, errMessage string, state util.State) {


	// If check type is manual, force result to WARN.
	if c.Type == "manual" {
		return output, errMessage, util.WARN
	}

	if c.Type == "skip" {
		return output, errMessage, util.INFO
	}

	// Check if command exists or exit with WARN.
	for _, cmd := range c.Commands {
		if !isShellCommand(cmd.Path) {
			glog.V(1).Infof("%s: command not found", cmd.Path)
			return output, errMessage, util.WARN
		}
	}

	// Run commands.
	n := len(c.Commands)
	if n == 0 {
		// Likely a warning message.
		return output, errMessage, util.WARN
	}

	out, err := exec.Command("sh", "-c", c.Audit).Output()

	if err != nil {
		errMessage = err.Error()
	}

	output = string(out)

	return output, errMessage, ""
}

func (c *Check) runAction(baseCheck BaseCheck) (out string, errmsgs string, state util.State) {

	// If check type is manual, force result to WARN.
	if baseCheck.Type == "manual" {
		return out, errmsgs, util.WARN
	}

	if baseCheck.Type == "skip" {
		return out, errmsgs, util.INFO
	}

	if baseCheck.Audit != "" {
		return out, util.HandleError(fmt.Errorf("yaml Audit entity is not supported in non shell mode"), reflect.TypeOf(c).String()), util.FAIL

	}
	searchFilter, err := actioneval.SearchFilterFactory(baseCheck.Action.CheckType, baseCheck.Action.Args, c.tarHeaders)
	if err != nil {
		return out, util.HandleError(err, reflect.TypeOf(c).String()), util.FAIL
	}
	if searchFilter == nil {
		return out, "Unsupported search type " + baseCheck.Action.CheckType, util.FAIL
	}
	var res = searchFilter.SearchFilterHandler(c.boundaryPath, baseCheck.Action.Count)
	return res.Output.String(), res.Errmsgs, res.State
}

func getFirstValidSubCheck(subChecks []SubCheck, definedConstraints map[string][]string) (subCheck *BaseCheck) {
	for _, sc := range subChecks {
		isSubCheckOk := true

		for testConstraintKey, testConstraintVals := range sc.Constraints {

			isSubCheckOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, definedConstraints)

			// If the sub check is not compatible with the constraints, move to the next one
			if !isSubCheckOk {
				break
			}
		}

		if isSubCheckOk {
			return &sc.BaseCheck
		}
	}

	return nil
}

func isSubCheckCompatible(testConstraintKey string, testConstraintVals []string, definedConstraints map[string][]string) bool {
	definedConstraintsVals := definedConstraints[testConstraintKey]

	// If the constraint's key is not defined - the check is not compatible
	if !(len(definedConstraintsVals) > 0) {
		return false
	}

	// For each constraint of the check under the specific key, check if its defined
	for _, val := range testConstraintVals {
		if !contains(definedConstraintsVals, val) {
			return false
		}
	}

	return true
}

func contains(arr []string, obj string) bool {
	for _, val := range arr {
		if val == obj {
			return true
		}
	}

	return false
}
