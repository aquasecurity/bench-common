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
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
	"strings"
)

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `json:"text"`
	Groups      []*Group `json:"tests"`
	Summary
	DefinedConstraints map[string][]string
	isAction           bool
	boundaryPath       string
	definitions        []string
	ids                []string
	tarHeaders         []tar.Header
	inYaml             []byte
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

func (controls *Controls) WithIsAction(isAction bool) *Controls {
	controls.isAction = isAction
	return controls
}

func (controls *Controls) WithBoundary(path string) *Controls {
	controls.boundaryPath = path
	return controls
}

func (controls *Controls) WithDefinitions(definitions []string) *Controls {
	controls.definitions = definitions
	return controls
}

func (controls *Controls) WithIds(ids ...string) *Controls {
	controls.ids = ids
	return controls
}

func (controls *Controls) WithTarHeaders(tarHeaders []tar.Header) *Controls {
	controls.tarHeaders = tarHeaders
	return controls
}

// NewControls instantiates a new master Controls object.
func NewControls(in []byte) *Controls {
	c := new(Controls)
	c.inYaml = in
	return c
}

func (controls *Controls) Build() (*Controls, error) {

	err := yaml.Unmarshal(controls.inYaml, controls)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}
	if !controls.isAction {
		// Prepare audit commands
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if check.SubChecks == nil {
					check.Commands = textToCommand(check.Audit)
				} else {
					for i, SubCheck := range check.SubChecks {
						check.SubChecks[i].Commands = textToCommand(SubCheck.Audit)
					}
				}
			}
		}
	}

	if len(controls.definitions) > 0 {
		controls.DefinedConstraints = map[string][]string{}
		for _, val := range controls.definitions {
			a := strings.Split(val, "=")

			// If its type 'category=value' for example 'platform=ubuntu'
			if len(a) == 2 && a[0] != "" && a[1] != "" {
				controls.DefinedConstraints[a[0]] = append(controls.DefinedConstraints[a[0]], a[1])
			} else {
				glog.V(1).Info("failed to parse defined constraint, ", val)
			}
		}
	}
	return controls, nil
}

func (controls *Controls) RunGroup() Summary {
	g := []*Group{}
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info = 0, 0, 0, 0

	// If no groupid is passed run all group checks.
	if len(controls.ids) == 0 {
		controls.ids = controls.getAllGroupIDs()
	}

	for _, group := range controls.Groups {
		for _, gid := range controls.ids {
			if gid == group.ID {
				for _, check := range group.Checks {
					check.WithAction(controls.isAction).
						WithBoundaryPath(controls.boundaryPath).
						WithTarHeaders(controls.tarHeaders).
						Run(controls.DefinedConstraints)

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
func (controls *Controls) RunChecks() Summary {
	g := []*Group{}
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info = 0, 0, 0, 0

	// If no group id is passed run all group checks.
	if len(controls.ids) == 0 {
		controls.ids = controls.getAllCheckIDs()
	}

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			for _, id := range controls.ids {
				if id == check.ID {
					check.WithAction(controls.isAction).
						WithBoundaryPath(controls.boundaryPath).
						WithTarHeaders(controls.tarHeaders).
						Run(controls.DefinedConstraints)
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

func summarize(controls *Controls, check *Check) {
	switch check.State {
	case util.PASS:
		controls.Summary.Pass++
	case util.FAIL:
		controls.Summary.Fail++
	case util.WARN:
		controls.Summary.Warn++
	case util.INFO:
		controls.Summary.Info++
	}
}

func summarizeGroup(group *Group, check *Check) {
	switch check.State {
	case util.PASS:
		group.Pass++
	case util.FAIL:
		group.Fail++
	case util.WARN:
		group.Warn++
	case util.INFO:
		group.Info++
	}
}
