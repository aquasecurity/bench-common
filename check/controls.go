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
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/golang/glog"
	"github.com/onsi/ginkgo/reporters"
)

// Auditer represents the Execute method to be called.
type Auditer interface {
	Execute(customConfig ...interface{}) (result string, errMsg string, state State)
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `json:"text"`
	Groups      []*Group `json:"tests"`
	Summary
	DefinedConstraints map[string][]string
	customConfigs      []interface{}
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

var defaultBench bench // for backward compatibility
// NewControls instantiates a new master Controls object.
func NewControls(in []byte, definitions []string) (*Controls, error) {
	return defaultBench.NewControls(in, definitions)
}

// RunGroup runs all checks in a group.
func (controls *Controls) RunGroup(gids ...string) Summary {
	g := []*Group{}
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info = 0, 0, 0, 0
	// If no group id is passed run all group checks.
	if len(gids) == 0 {
		gids = controls.getAllGroupIDs()
	}

	for _, group := range controls.Groups {
		for _, gid := range gids {
			if gid == group.ID {
				for _, check := range group.Checks {
					// Check if group has constraints
					if group.Constraints != nil {
						groupConstraintsOk := true
						for testConstraintKey, testConstraintVals := range group.Constraints {
							groupConstraintsOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, controls.DefinedConstraints)
							// If group constraints is not applied then skip test.
							if !groupConstraintsOk {
								check.Type = SKIP
							}
						}
					}
					if group.Type == SKIP {
						check.Type = SKIP
					}
					check.Run(controls.DefinedConstraints)
					check.TestInfo = append(check.TestInfo, check.Remediation)
					summarize(controls, check)
					summarizeGroup(group, check)
				}

				g = append(g, group)
			}
		}

	}

	controls.Groups = g
	return controls.Summary
}

// RunChecks runs the checks with the supplied IDs.
func (controls *Controls) RunChecks(ids ...string) Summary {
	g := []*Group{}
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info = 0, 0, 0, 0

	// If no groupid is passed run all group checks.
	if len(ids) == 0 {
		ids = controls.getAllCheckIDs()
	}

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			for _, id := range ids {
				if id == check.ID {
					check.Run(controls.DefinedConstraints)
					check.TestInfo = append(check.TestInfo, check.Remediation)
					summarize(controls, check)

					// Check if we have already added this checks group.
					if v, ok := m[group.ID]; !ok {
						// Create a group with same info
						w := &Group{
							ID:          group.ID,
							Description: group.Description,
							Checks:      []*Check{},
						}

						// Add this check to the new group
						w.Checks = append(w.Checks, check)

						// Add to groups we have visited.
						m[w.ID] = w
						g = append(g, w)
					} else {
						v.Checks = append(v.Checks, check)
					}

				}
			}
		}
	}

	controls.Groups = g
	return controls.Summary
}

func (controls *Controls) getAllGroupIDs() []string {
	var ids []string

	for _, group := range controls.Groups {
		ids = append(ids, group.ID)
	}
	return ids
}

func (controls *Controls) getAllCheckIDs() []string {
	var ids []string

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			ids = append(ids, check.ID)
		}
	}
	return ids

}

// JSON encodes the results of last run to JSON.
func (controls *Controls) JSON() ([]byte, error) {
	return json.Marshal(controls)
}

// JUnit encodes the results of last run to JUnit.
func (controls *Controls) JUnit() ([]byte, error) {
	suite := reporters.JUnitTestSuite{
		Name:      controls.Description,
		TestCases: []reporters.JUnitTestCase{},
		Tests:     controls.Summary.Pass + controls.Summary.Fail + controls.Summary.Info + controls.Summary.Warn,
		Failures:  controls.Summary.Fail,
	}
	for _, g := range controls.Groups {
		for _, check := range g.Checks {
			jsonCheck := ""
			jsonBytes, err := json.Marshal(check)
			if err != nil {
				jsonCheck = fmt.Sprintf("Failed to marshal test into JSON: %v. Test as text: %#v", err, check)
			} else {
				jsonCheck = string(jsonBytes)
			}
			tc := reporters.JUnitTestCase{
				Name:      fmt.Sprintf("%v %v", check.ID, check.Description),
				ClassName: g.Description,

				// Store the entire json serialization as system out so we don't lose data in cases where deeper debugging is necessary.
				SystemOut: jsonCheck,
			}

			switch check.State {
			case FAIL:
				tc.FailureMessage = &reporters.JUnitFailureMessage{Message: check.Remediation}
			case WARN, INFO:
				// WARN and INFO are two different versions of skipped tests. Either way it would be a false positive/negative to report
				// it any other way.
				tc.Skipped = &reporters.JUnitSkipped{}
			case PASS:
			default:
				glog.Warningf("Unrecognized state %s", check.State)
			}

			suite.TestCases = append(suite.TestCases, tc)
		}
	}

	var b bytes.Buffer
	encoder := xml.NewEncoder(&b)
	encoder.Indent("", "    ")
	err := encoder.Encode(suite)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate JUnit report: %s", err.Error())
	}

	return b.Bytes(), nil
}

func summarize(controls *Controls, check *Check) {
	switch check.State {
	case PASS:
		controls.Summary.Pass++
	case FAIL:
		controls.Summary.Fail++
	case WARN:
		controls.Summary.Warn++
	case INFO:
		controls.Summary.Info++
	}
}

func summarizeGroup(group *Group, check *Check) {
	switch check.State {
	case PASS:
		group.Pass++
	case FAIL:
		group.Fail++
	case WARN:
		group.Warn++
	case INFO:
		group.Info++
	}
}
