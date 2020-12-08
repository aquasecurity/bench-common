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
	"strings"
	"testing"

	"github.com/onsi/ginkgo/reporters"
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
      scored: false
    - id: 1.1.4
      text: "More than one test with tests rather than subchecks"
      audit: "echo test"
      tests:
        test_items:
        - flag: "test"
          set: true			  
      remediation: "Make it work"
      scored: true
- id: 2.1
  text: "API Server"
  type: "skip"
  checks:
    - id: 2.1.1
      type: "skip"
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
    - id: 2.1.2
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
    - id: 2.1.3
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
const (
	PASSIndex = 0
	FAILIndex = 1
	WARNIndex = 2
	INFOIndex = 3
)

var definedTestConstraints = []string{"platform=ubuntu", "platform=rhel", "boot=grub"}

func TestRunGroup(t *testing.T) {

	type TestCase struct {
		name     string
		groupIDs []string
		Expected [4]int
	}
	testCases := []TestCase{
		{name: "test 1 - skip group", groupIDs: []string{"2.1"}, Expected: [4]int{0, 0, 0, 3}},
		{name: "test 2 - regular group", groupIDs: []string{"1.1"}, Expected: [4]int{1, 2, 1, 0}},
		{name: "test 3 - skip and regular group", groupIDs: []string{"1.1", "2.1"}, Expected: [4]int{1, 2, 1, 3}},
	}
	for _, test := range testCases {

		c, err := NewControls([]byte(def), definedTestConstraints)
		if err != nil {
			t.Fatalf("could not create control object: %s", err)
		}

		output := c.RunGroup(test.groupIDs...)
		if !(output.Pass == test.Expected[PASSIndex] && output.Fail == test.Expected[FAILIndex] && output.Warn == test.Expected[WARNIndex] && output.Info == test.Expected[INFOIndex]) {
			t.Errorf("%s failed\nexpected: PASS[%d] FAIL[%d] WARN[%d] INFO[%d] got:\nPASS[%d] FAIL[%d] WARN[%d] INFO[%d]\n", test.name, test.Expected[PASSIndex], test.Expected[FAILIndex], test.Expected[WARNIndex], test.Expected[INFOIndex], output.Pass, output.Fail, output.Warn, output.Info)
		}
	}
}

func TestRunChecks(t *testing.T) {

	type TestCase struct {
		name     string
		checks   []string
		Expected [4]int
	}
	testCases := []TestCase{
		{name: "test 1 - one skip test", checks: []string{"2.1.1"}, Expected: [4]int{0, 0, 0, 1}},
		{name: "test 2 - one fail test", checks: []string{"1.1.2"}, Expected: [4]int{0, 1, 0, 0}},
		{name: "test 3 - one pass test", checks: []string{"1.1.4"}, Expected: [4]int{1, 0, 0, 0}},
		{name: "test 4 - one pass test", checks: []string{"1.1.3"}, Expected: [4]int{0, 0, 1, 0}},
		{name: "test 5 - one fail and one skip tests", checks: []string{"1.1.2", "2.1.1"}, Expected: [4]int{0, 1, 0, 1}},
		{name: "test 6 - two fail tests one skip test", checks: []string{"1.1.2", "2.1.2", "2.1.1"}, Expected: [4]int{0, 2, 0, 1}},
		{name: "test 7 - one of each", checks: []string{"1.1.3", "1.1.2", "2.1.1", "1.1.4"}, Expected: [4]int{1, 1, 1, 1}},
	}

	for _, test := range testCases {

		c, err := NewControls([]byte(def), definedTestConstraints)
		if err != nil {
			t.Fatalf("could not create control object: %s", err)
		}

		output := c.RunChecks(test.checks...)
		if !(output.Pass == test.Expected[PASSIndex] && output.Fail == test.Expected[FAILIndex] && output.Warn == test.Expected[WARNIndex] && output.Info == test.Expected[INFOIndex]) {
			t.Errorf("%s failed\nexpected: PASS[%d] FAIL[%d] WARN[%d] INFO[%d] got:\nPASS[%d] FAIL[%d] WARN[%d] INFO[%d]\n", test.name, test.Expected[PASSIndex], test.Expected[FAILIndex], test.Expected[WARNIndex], test.Expected[INFOIndex], output.Pass, output.Fail, output.Warn, output.Info)
		}

	}
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

func TestControls_JUnitIncludesJSON(t *testing.T) {
	testCases := []struct {
		desc   string
		input  *Controls
		expect []byte
	}{
		{
			desc: "Serializes to junit",
			input: &Controls{
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Description: "check1text", State: PASS},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="0" failures="0" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
</testsuite>`),
		},
		{
			desc: "Summary values come from summary not checks",
			input: &Controls{
				Summary: Summary{
					Fail: 99,
					Pass: 100,
					Warn: 101,
					Info: 102,
				},
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Description: "check1text", State: PASS},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="402" failures="99" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
</testsuite>`),
		},
		{
			desc: "Warn and Info are considered skips and failed tests properly reported",
			input: &Controls{
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Description: "check1text", State: PASS},
							{ID: "check2id", Description: "check2text", State: INFO},
							{ID: "check3id", Description: "check3text", State: WARN},
							{ID: "check4id", Description: "check4text", State: FAIL},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="0" failures="0" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
    <testcase name="check2id check2text" classname="" time="0">
        <skipped></skipped>
        <system-out>{&#34;test_number&#34;:&#34;check2id&#34;,&#34;test_desc&#34;:&#34;check2text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;INFO&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
    <testcase name="check3id check3text" classname="" time="0">
        <skipped></skipped>
        <system-out>{&#34;test_number&#34;:&#34;check3id&#34;,&#34;test_desc&#34;:&#34;check3text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;WARN&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
    <testcase name="check4id check4text" classname="" time="0">
        <failure type=""></failure>
        <system-out>{&#34;test_number&#34;:&#34;check4id&#34;,&#34;test_desc&#34;:&#34;check4text&#34;,&#34;SubChecks&#34;:null,&#34;audit_type&#34;:&#34;&#34;,&#34;audit&#34;:null,&#34;type&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;FAIL&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;expected_result&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false}</system-out>
    </testcase>
</testsuite>`),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			junitBytes, err := tc.input.JUnit()
			if err != nil {
				t.Fatalf("Failed to serialize to JUnit: %v", err)
			}

			var out reporters.JUnitTestSuite
			if err := xml.Unmarshal(junitBytes, &out); err != nil {
				t.Fatalf("Unable to deserialize from resulting JUnit: %v", err)
			}

			// Check that each check was serialized as json and stored as systemOut.
			for iGroup, group := range tc.input.Groups {
				for iCheck, check := range group.Checks {
					jsonBytes, err := json.Marshal(check)
					if err != nil {
						t.Fatalf("Failed to serialize to JUnit: %v", err)
					}

					if strings.TrimSpace(out.TestCases[iGroup*iCheck+iCheck].SystemOut) != strings.TrimSpace(string(jsonBytes)) {
						t.Errorf("Expected\n%v\n\tbut got\n%q",
							out.TestCases[iGroup*iCheck+iCheck].SystemOut,
							string(jsonBytes),
						)
					}
				}
			}

			if !bytes.Equal(junitBytes, tc.expect) {
				t.Errorf("Expected\n\t%v\n\tbut got\n\t%v",
					string(tc.expect),
					string(junitBytes),
				)
			}
		})
	}
}
