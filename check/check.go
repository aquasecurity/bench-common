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
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aquasecurity/bench-common/auditeval"
	"github.com/golang/glog"
)

// State is the state of a control check.
type State string

// AuditType is the type of audit to test.
type AuditType string

// TypeAudit string representing default "Audit".
const TypeAudit = "audit"

// Audit string that holds audit to execute.
type Audit string

// Execute method called by the main logic to execute the Audit's Execute type.
func (audit Audit) Execute(customConfig ...interface{}) (result string, errMessage string, state State) {

	res, err := runAudit(string(audit))

	// Errors mean the audit command failed, but that might be what we expect
	// for example, if we grep for something that is not found, there is a non-zero exit code
	// It is a problem if we can't find one of the audit commands to execute, but we deal
	// with this case in (c *Check) Run()
	if err != nil {
		errMessage = err.Error()
	}
	return string(res), errMessage, ""
}

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL = "FAIL"
	// WARN could not carry out check.
	WARN = "WARN"
	// INFO informational message
	INFO = "INFO"
	// SKIP for when a check should be skipped.
	SKIP = "skip"
)

func handleError(err error, context string) (errmsg string) {
	if err != nil {
		errmsg = fmt.Sprintf("%s, error: %s\n", context, err)
	}
	return
}

// BaseCheck (Original version) - checks don't have sub checks, each check has only one sub check as part of the check itself
type BaseCheck struct {
	AuditType     AuditType           `json:"audit_type"`
	Audit         interface{}         `json:"audit"`
	Type          string              `json:"type"`
	Commands      []*exec.Cmd         `json:"-"`
	Tests         *auditeval.Tests    `json:"-"`
	Remediation   string              `json:"-"`
	Constraints   map[string][]string `yaml:"constraints"`
	auditer       Auditer
	customConfigs []interface{}
}

// SubCheck additional check to be performed.
type SubCheck struct {
	BaseCheck `yaml:"check"`
}

// Check contains information about a recommendation.
type Check struct {
	ID             string           `yaml:"id" json:"test_number"`
	Description    string           `json:"test_desc"`
	Text           string           `json:"-"`
	Set            bool             `json:"-"`
	SubChecks      []*SubCheck      `yaml:"sub_checks"`
	AuditType      AuditType        `json:"audit_type"`
	Audit          interface{}      `json:"audit"`
	Type           string           `json:"type"`
	Commands       []*exec.Cmd      `json:"-"`
	Tests          *auditeval.Tests `json:"-"`
	Remediation    string           `json:"-"`
	TestInfo       []string         `json:"test_info"`
	State          `json:"status"`
	ActualValue    string `json:"actual_value"`
	ExpectedResult string `json:"expected_result"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`
	auditer        Auditer
	customConfigs  []interface{}
	Reason         string `json:"reason,omitempty"`
}

// Group is a collection of similar checks.
type Group struct {
	ID          string              `yaml:"id" json:"section"`
	Description string              `json:"desc"`
	Text        string              `json:"-"`
	Constraints map[string][]string `yaml:"constraints"`
	Type        string              `yaml:"type" json:"type"`
	Checks      []*Check            `json:"results"`
	Pass        int                 `json:"pass"` // Tests with no type that passed
	Fail        int                 `json:"fail"` // Tests with no type that failed
	Warn        int                 `json:"warn"` // Tests of type manual won't be run and will be marked as Warn
	Info        int                 `json:"info"` // Tests of type skip won't be run and will be marked as Info
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) Run(definedConstraints map[string][]string) {
	glog.V(3).Infof("----- Running check %v -----", c.ID)
	// If check type is skip, force result to INFO
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.State = INFO
		glog.V(3).Info(c.Reason)
		return
	}

	//If check type is manual, force result to WARN
	if c.Type == "manual" {
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return
	}

	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if len(strings.TrimSpace(c.Type)) == 0 && c.Tests == nil && c.SubChecks == nil {
		c.Reason = "There are no test items"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return
	}

	var subCheck *BaseCheck
	if c.SubChecks == nil {
		subCheck = &BaseCheck{
			Commands:      c.Commands,
			Tests:         c.Tests,
			Type:          c.Type,
			Audit:         c.Audit,
			Remediation:   c.Remediation,
			AuditType:     c.AuditType,
			auditer:       c.auditer,
			customConfigs: c.customConfigs,
		}
	} else {
		subCheck = getFirstValidSubCheck(c.SubChecks, definedConstraints)

		if subCheck == nil {
			c.Reason = "Failed to find a valid sub check, check your constraints "
			c.State = WARN
			glog.V(1).Info("Failed to find a valid sub check, check your constraints")
			glog.V(3).Info(c.Reason)
			return
		}
	}

	var out, errmsgs string

	out, errmsgs, c.State = runAuditCommands(*subCheck)

	if errmsgs != "" {
		glog.V(2).Info(errmsgs)
		c.Reason = out
		// Make output more readable
		if (errmsgs == "exit status 127" || errmsgs == "exit status 1") && strings.HasSuffix(out, "not found\n") {
			c.Reason = strings.Replace(c.Reason, "sh: 1:", "Command", -1)
			glog.V(3).Info(c.Reason)
		}
	}

	if c.State != "" {
		return
	}

	finalOutput := subCheck.Tests.Execute(out, c.ID, c.IsMultiple)

	if finalOutput != nil {
		c.ActualValue = finalOutput.ActualResult
		c.ExpectedResult = finalOutput.ExpectedResult

		if finalOutput.TestResult {
			c.State = PASS
		} else if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
	} else {
		c.State = WARN
		glog.V(1).Info("Test output contains a nil value")
		c.Reason = "Test output contains a nil value"
		glog.V(3).Info(c.Reason)
		return
	}
	glog.V(3).Infof("TestResult: %t, State: %q \n ", finalOutput.TestResult, c.State)
}

func runAudit(audit string) (output string, err error) {
	var out bytes.Buffer

	audit = strings.TrimSpace(audit)
	if len(audit) == 0 {
		return output, err
	}

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output = out.String()

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, output, err)
	} else {
		glog.V(3).Infof("Command %q ", audit)
		glog.V(3).Infof("Output: %q", output)

	}
	return output, err
}

func runAuditCommands(c BaseCheck) (output, errMessage string, state State) {

	// If check type is manual, force result to WARN.
	if c.Type == "manual" {
		return output, errMessage, WARN
	}

	if c.Type == "skip" {
		return output, errMessage, INFO
	}
	if c.auditer != nil {
		if len(c.customConfigs) == 0 {
			c.customConfigs = append(c.customConfigs, c.Audit)
		}
		return c.auditer.Execute(c.customConfigs...)
	}
	return
}

func getFirstValidSubCheck(subChecks []*SubCheck, definedConstraints map[string][]string) (subCheck *BaseCheck) {
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
		if contains(definedConstraintsVals, val) {
			return true
		}
	}

	return false
}

func contains(arr []string, obj string) bool {
	for _, val := range arr {
		if val == obj {
			return true
		}
	}

	return false
}
