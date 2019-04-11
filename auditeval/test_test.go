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

package auditeval

import (
	"testing"

	yaml "gopkg.in/yaml.v2"
)

const def1 = `
---
tests:
bin_op: or
test_items:
- flag: "enabled"
  compare:
    op: has
    value: enabled
  set: true
`

const testMultiple = `
---
tests:
bin_op: and
test_items:
- flag: "User"
  compare:
    op: nothave
    value: "root"
  set: true
- flag: "User"
  compare:
    op: noteq
    value: ""
  set: true
- flag: "User"
  compare:
    op: noteq
    value: "1"
  set: true
`

// TODO: Write more test cases.
func TestTestExecute(t *testing.T) {
	ts := new(Tests)
	if err := yaml.Unmarshal([]byte(def1), ts); err != nil {
		t.Fatalf("error unmarshaling tests yaml")
	}

	cases := []struct {
		str  string
		want bool
	}{
		{"configuration is enabled", true},
		{"The cow jumped over the moon", false},
	}

	for _, c := range cases {
		res := ts.Execute(c.str, false)
		if res.TestResult != c.want {
			t.Errorf("expected:%v, got:%v\n", c.want, res)
		}
	}
}

func Test_getFlagValue(t *testing.T) {

	type TestRegex struct {
		Input    string
		Flag     string
		Expected string
	}

	tests := []TestRegex{
		{Input: "XXX: User=root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User=", Flag: "User", Expected: ""},
		{Input: "XXX: User= AAA XXX", Flag: "User", Expected: ""},
		{Input: "XXX: XXX User=some_user XXX", Flag: "User", Expected: "some_user"},
		{Input: "--flag=AAA,BBB,CCC XXX", Flag: "--flag", Expected: "AAA,BBB,CCC"},
		{Input: "--flag", Flag: "--flag", Expected: "--flag"},
		{Input: "XXX --flag AAA XXX", Flag: "--flag", Expected: "AAA"},
		{Input: "XXX --AAA BBB", Flag: "XXX", Expected: "XXX"},
		{Input: "XXX", Flag: "XXX", Expected: "XXX"},
		{Input: "CCC XXX AAA BBB", Flag: "XXX", Expected: "AAA"},
		{Input: "YXXX", Flag: "XXX", Expected: ""},
		{Input: "XXXY", Flag: "XXX", Expected: ""},
	}

	for i, test := range tests {
		actual := getFlagValue(test.Input, test.Flag)
		if test.Expected != actual {
			t.Errorf("test %d fail: expected: %v actual: %v\ntest details: %+v\n", i, test.Expected, actual, test)
		}
	}
}

// Test for multi-output functionality
// Some of the tests checks for a list of results in the single output
// These tests should set the flag "use_multiple_values" to true
// Testing for multiple values in output with the flag set/not-set and for different combinations of results
// Test simulation is number 4.1 in docker-bench 17.06 yaml file
func Test_ExecuteMultipleOutput(t *testing.T) {
	//    audit: "docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}'"
	//    use_multiple_values: true/false

	ts := new(Tests)
	if err := yaml.Unmarshal([]byte(testMultiple), ts); err != nil {
		t.Fatalf("error unmarshaling tests yaml")
	}

	cases := []struct {
		auditCommandOutput  string
		expectedResult bool
		testWithMultiple bool
	}{
		// If the use_multiple_values is not set, test should pass on first container (The bug)
		{`b24f2b421ec7742ad6417263c34fcc1086e83ca6b9d4f759ff8671a0f9fc68ac: User=Pass
			9bf99c968c5a96c9d7913609867deffce0d59b90429a7e6a584485eec69067d1: User=
			af1072975e9e129489a75b9aa3cac7cc613bda4901e0ca2369366a7297d3e3ca: User=`,
		true, false,
		},
		// If the use_multiple_values is not set, test should fail on first container
		{`b24f2b421ec7742ad6417263c34fcc1086e83ca6b9d4f759ff8671a0f9fc68ac: User=
			9bf99c968c5a96c9d7913609867deffce0d59b90429a7e6a584485eec69067d1: User=ShouldFail
			af1072975e9e129489a75b9aa3cac7cc613bda4901e0ca2369366a7297d3e3ca: User=NoUse`,
			false, false,
		},
		// If the use_multiple_values is set, test should fail on second container (first to fail the test)
		{`b24f2b421ec7742ad6417263c34fcc1086e83ca6b9d4f759ff8671a0f9fc68ac: User=Pass
			9bf99c968c5a96c9d7913609867deffce0d59b90429a7e6a584485eec69067d1: User=
			af1072975e9e129489a75b9aa3cac7cc613bda4901e0ca2369366a7297d3e3ca: User=`,
			false, true,
		},
		// If the use_multiple_values is set, test should fail on first container (first to fail the test)
		{`b24f2b421ec7742ad6417263c34fcc1086e83ca6b9d4f759ff8671a0f9fc68ac: User=root
			9bf99c968c5a96c9d7913609867deffce0d59b90429a7e6a584485eec69067d1: User=a
			af1072975e9e129489a75b9aa3cac7cc613bda4901e0ca2369366a7297d3e3ca: User=b`,
			false, true,
		},
		// If the use_multiple_values is set, test should pass
		{`b24f2b421ec7742ad6417263c34fcc1086e83ca6b9d4f759ff8671a0f9fc68ac: User=Pass
			9bf99c968c5a96c9d7913609867deffce0d59b90429a7e6a584485eec69067d1: User=Pass1
			af1072975e9e129489a75b9aa3cac7cc613bda4901e0ca2369366a7297d3e3ca: User=Pass`,
			true, true,
		},
	}

	for _, c := range cases {
		res := ts.Execute(c.auditCommandOutput, c.testWithMultiple)
		if res.TestResult != c.expectedResult {
			t.Errorf("expected:%v, got:%v\n", c.expectedResult, res.TestResult)
		}
	}
}
