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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang/glog"

	"gopkg.in/yaml.v2"
)

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
	auditTypeRegistry  map[AuditType]func() interface{}
	customConfigs      []interface{}
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

// NewControls instantiates a new master Controls object.
func NewControls(in []byte, definitions []string, customConfigs ...interface{}) (*Controls, error) {

	c := new(Controls)
	c.auditTypeRegistry = make(map[AuditType]func() interface{})
	err := yaml.Unmarshal(in, c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}

	c.customConfigs = customConfigs
	if len(definitions) > 0 {
		c.DefinedConstraints = map[string][]string{}
		for _, val := range definitions {
			a := strings.Split(val, "=")

			// If its type 'category=value' for example 'platform=ubuntu'
			if len(a) == 2 && a[0] != "" && a[1] != "" {
				c.DefinedConstraints[a[0]] = append(c.DefinedConstraints[a[0]], a[1])
			} else {
				glog.V(1).Info("failed to parse defined constraint, ", val)
			}
		}
	}

	return c, nil
}

func (controls *Controls) convertAuditToRegisteredType(auditType AuditType, audit interface{}) (auditer Auditer, err error) {

	var auditBytes []byte
	var callback func() interface{}
	var ok bool

	if auditType == "" || auditType == TypeAudit {
		if s, ok := audit.(string); ok || audit == nil {
			return Audit(s), nil
		}
		return nil, fmt.Errorf("failed to convert audit, mismatching type")
	}

	if callback, ok = controls.auditTypeRegistry[auditType]; !ok {
		return nil, fmt.Errorf("audit type %v is not registered", auditType)
	}

	o := callback()
	if auditBytes, err = yaml.Marshal(audit); err == nil {
		return nil, fmt.Errorf("unable to marshal Audit %v", err)
	}

	if err := yaml.Unmarshal(auditBytes, o); err != nil {
		return nil, fmt.Errorf("unable to Unmarshal Audit %v", err)
	}
	return o.(Auditer), nil
}

func (controls *Controls) RegisterAuditType(auditType AuditType, typeCallback func() interface{}) error {

	if _, ok := controls.auditTypeRegistry[auditType]; ok {
		return fmt.Errorf("audit type %v already registered", auditType)
	}
	a := typeCallback()
	if _, ok := a.(Auditer); ok {
		controls.auditTypeRegistry[auditType] = typeCallback
		return nil
	}
	return fmt.Errorf("audit type %v must implement Auditer interface", auditType)

}

func extractAllAudits(controls *Controls) (err error) {
	var audit Auditer
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if check.SubChecks == nil {
				if audit, err = controls.convertAuditToRegisteredType(check.AuditType, check.Audit); err == nil {
					check.auditer = audit
					check.customConfigs = controls.customConfigs
				}
				return err
			} else {
				for _, subCheck := range check.SubChecks {
					if audit, err = controls.convertAuditToRegisteredType(subCheck.AuditType, subCheck.Audit); err == nil {
						subCheck.auditer = audit
						subCheck.customConfigs = controls.customConfigs
					}
					return err
				}
			}
		}
	}
	return nil
}

// RunGroup runs all checks in a group.
func (controls *Controls) RunGroup(gids ...string) Summary {
	g := []*Group{}
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info = 0, 0, 0, 0
	err := extractAllAudits(controls)
	if err != nil {
		glog.V(1).Infof("failed to extract audit %v", err)
		return controls.Summary
	}
	// If no group id is passed run all group checks.
	if len(gids) == 0 {
		gids = controls.getAllGroupIDs()
	}

	for _, group := range controls.Groups {
		for _, gid := range gids {
			if gid == group.ID {
				for _, check := range group.Checks {
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
	err := extractAllAudits(controls)
	if err != nil {
		glog.V(1).Infof("failed to extract audit %v", err)
		return controls.Summary
	}

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
