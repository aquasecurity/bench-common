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
	"testing"
)

const def = `---
controls:
id: 1
text: "Master Node Security Configuration"
type: "master"
groups:
- id: 1.1
  text: "API Server"
  checks:
    - id: 1.1.1
      text: "Ensure that the --allow-privileged argument is set to false (Scored)"
      audit: "ps -ef | grep $apiserverbin | grep -v grep"
      tests:
        test_items:
        - flag: "allow-privileged"
          compare:
            op: eq
            value: false
          set: true
      remediation: "Edit the $apiserverconf file on the master node and set 
              the KUBE_ALLOW_PRIV parameter to \"--allow-privileged=false\""
      scored: true
    - id: 1.1.2
      text: "Ensure that the --allow-privileged argument is set to false (Scored)"
      sub_checks:
      - check:
        audit: "this is a subcheck audit string"
        tests:
          test_items:
          - flag: "allow-privileged"
            compare:
              op: eq
              value: false
            set: true			  
      remediation: "Make it work"
      scored: true
    - id: 1.1.3
      text: "More than one test with tests rather than subchecks"
      audit: "some other audit string"
      tests:
        test_items:
        - flag: "allow-privileged"
          compare:
            op: eq
            value: false
          set: true			  
      remediation: "Make it work"
      scored: true
`

var definedTestConstraints = []string{"platform=ubuntu", "platform=rhel", "boot=grub"}

func TestRunGroup(t *testing.T) {
	c, err := NewControls([]byte(def), definedTestConstraints)
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	c.RunGroup()
}

// TODO: make this test useful as of now it never fails.
func TestRunChecks(t *testing.T) {
	c, err := NewControls([]byte(def), definedTestConstraints)
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	c.RunChecks("1.1.2")
}

func TestSummarizeGroup(t *testing.T) {
	type TestCase struct {
		state    State
		group    Group
		check    Check
		Expected int
	}
	var actual int

	testCases := []TestCase{
		{group: Group{}, check: Check{State: "PASS"}, Expected: 1},
		{group: Group{}, check: Check{State: "FAIL"}, Expected: 1},
		{group: Group{}, check: Check{State: "WARN"}, Expected: 1},
		{group: Group{}, check: Check{State: "INFO"}, Expected: 1},
	}
	for i, test := range testCases {
		summarizeGroup(&test.group, &test.check)
		switch test.check.State {
		case "PASS":
			actual = test.group.Pass
		case "FAIL":
			actual = test.group.Fail
		case "WARN":
			actual = test.group.Warn
		case INFO:
			actual = test.group.Info
		}

		if actual != test.Expected {
			t.Errorf("test %d fail: expected: %v actual: %v\ntest details: %+v\n", i, test.Expected, actual, test)
		}
	}
}

func TestExtractAllAudits(t *testing.T) {

	c, err := NewControls([]byte(def), nil)
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	err = extractAllAudits(c)
	if err != nil {
		t.Fatalf("test failed: %v", err)
	}

	for _, g := range c.Groups {
		for _, c := range g.Checks {

			if c.Audit != nil && c.Audit != "" {
				if c.auditer == nil {
					t.Errorf("ID %s: Unexpected nil auditer", c.ID)
					continue
				}
				audit, ok := c.auditer.(Audit)
				if !ok {
					t.Errorf("ID %s: Couldn't convert auditer %v to Audit", c.ID, c.auditer)
				}

				if string(audit) != c.Audit {
					t.Errorf("ID %s: extracted audit %s, doesn't match audit string %s", c.ID, string(audit), c.Audit)
				}
			}

			for _, s := range c.SubChecks {
				if s.auditer == nil {
					t.Errorf("ID %s: Unexpected nil auditer", c.ID)
					continue
				}
				audit, ok := s.auditer.(Audit)
				if !ok {
					t.Errorf("ID %s: Couldn't convert auditer %v to Audit", c.ID, s.auditer)
				}
				if string(audit) != s.Audit {
					t.Errorf("ID %s: extracted audit %s, expected %s", c.ID, string(audit), s.Audit)
				}
			}
		}
	}
}
