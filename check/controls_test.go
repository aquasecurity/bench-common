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
      scored: true`

func TestRunGroup(t *testing.T) {
	c, err := NewControls([]byte(def))
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	c.RunGroup()
}

// TODO: make this test useful as of now it never fails.
func TestRunChecks(t *testing.T) {
	c, err := NewControls([]byte(def))
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	c.RunChecks("1.1.2")
}

func TestSummarizeGroup(t *testing.T) {
		type TestCase struct {
			state State
			group Group
			check Check
			Expected int
		}
		var actual int

		testCases := []TestCase{
			{group:Group{},  check:Check{State: "PASS"}, Expected: 1},
			{group:Group{},  check:Check{State: "FAIL"}, Expected: 1},
			{group:Group{},  check:Check{State: "WARN"}, Expected: 1},
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
			}
			if actual != test.Expected {
				t.Errorf("test %d fail: expected: %v actual: %v\ntest details: %+v\n", i, test.Expected, actual, test)
			}
		}
}
