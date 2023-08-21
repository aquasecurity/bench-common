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

package check

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bench implementer of this interface represent audit types to be tests.
type Bench interface {
	RegisterAuditType(auditType AuditType, typeCallback func() interface{}) error
	NewControls(in []byte, definitions []string, customConfigs ...interface{}) (*Controls, error)
}

type bench struct {
	auditTypeRegistry map[AuditType]func() interface{}
}

// NewBench returns a new Bench
func NewBench() Bench {
	return &bench{auditTypeRegistry: make(map[AuditType]func() interface{})}
}

func (b *bench) RegisterAuditType(auditType AuditType, typeCallback func() interface{}) error {

	if _, ok := b.auditTypeRegistry[auditType]; ok {
		return fmt.Errorf("audit type %v already registered", auditType)
	}
	a := typeCallback()
	if _, ok := a.(Auditer); ok {
		b.auditTypeRegistry[auditType] = typeCallback
		return nil
	}
	return fmt.Errorf("audit type %v must implement Auditer interface", auditType)

}

func (b *bench) NewControls(in []byte, definitions []string, customConfigs ...interface{}) (*Controls, error) {
	c := new(Controls)
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
			}
		}
	}
	if err := b.extractAllAudits(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (b *bench) convertAuditToRegisteredType(auditType AuditType, audit interface{}) (auditer Auditer, err error) {

	var auditBytes []byte
	var callback func() interface{}
	var ok bool

	if auditType == "" || auditType == TypeAudit {
		if s, ok := audit.(string); ok || audit == nil {
			return Audit(s), nil
		}
		return nil, fmt.Errorf("failed to convert audit, mismatching type")
	}

	if callback, ok = b.auditTypeRegistry[auditType]; !ok {
		return nil, fmt.Errorf("audit type %v is not registered", auditType)
	}

	o := callback()
	if auditBytes, err = yaml.Marshal(audit); err != nil {
		return nil, fmt.Errorf("unable to marshal Audit %v", err)
	}

	if err := yaml.Unmarshal(auditBytes, o); err != nil {
		return nil, fmt.Errorf("unable to Unmarshal Audit %v", err)
	}
	return o.(Auditer), nil
}

func (b *bench) extractAllAudits(controls *Controls) (err error) {
	var audit Auditer
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if check.SubChecks == nil {
				if audit, err = b.convertAuditToRegisteredType(check.AuditType, check.Audit); err != nil {
					return err
				}
				check.auditer = audit
				check.customConfigs = controls.customConfigs
			} else {
				for _, subCheck := range check.SubChecks {
					if audit, err = b.convertAuditToRegisteredType(subCheck.AuditType, subCheck.Audit); err != nil {
						return err
					}
					subCheck.auditer = audit
					subCheck.customConfigs = controls.customConfigs
				}
			}
		}
	}
	return err
}
