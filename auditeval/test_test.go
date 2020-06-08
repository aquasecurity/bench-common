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
	"fmt"
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

	for i, c := range cases {
		res := ts.Execute(c.str, string(i), false)
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
		// Check for expecting values after '=' with various space cases
		{Input: "XXX: User=root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User =root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User= root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User = root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User =	root XXX", Flag: "User", Expected: "root"},
		// Check for expecting values after ':' with various space cases
		{Input: "XXX: User:root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User :root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User: root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User : root XXX", Flag: "User", Expected: "root"},
		// Check for expecting values after '=' with various space cases
		{Input: "XXX: User=root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User =root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User= root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User = root XXX", Flag: "User", Expected: "root"},
		// Check for expecting values with '_' separating the values
		{Input: "XXX: User=some_user XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User =some_user XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User= some_user XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User = some_user XXX", Flag: "User", Expected: "some_user"},
		// Check for expecting values with '.' separating the values
		{Input: "XXX: User=some.user XXX", Flag: "User", Expected: "some.user"},
		{Input: "XXX: User =some.user XXX", Flag: "User", Expected: "some.user"},
		{Input: "XXX: User= some.user XXX", Flag: "User", Expected: "some.user"},
		{Input: "XXX: User = some.user XXX", Flag: "User", Expected: "some.user"},
		// Check for expecting values with ',' separating the values
		{Input: "XXX: User=pikachu,charizard,bulbasaur XXX", Flag: "User", Expected: "pikachu,charizard,bulbasaur"},
		{Input: "XXX: User =pikachu,charizard,bulbasaur XXX", Flag: "User", Expected: "pikachu,charizard,bulbasaur"},
		{Input: "XXX: User= pikachu,charizard,bulbasaur XXX", Flag: "User", Expected: "pikachu,charizard,bulbasaur"},
		{Input: "XXX: User = pikachu,charizard,bulbasaur XXX", Flag: "User", Expected: "pikachu,charizard,bulbasaur"},
		// Check for expecting values with in "" separating the values
		{Input: "XXX: User=\"some_user\" XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User =\"some_user\" XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User= \"some_user\" XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User = \"some_user\" XXX", Flag: "User", Expected: "some_user"},
		{Input: "XXX: User=\"gotta catch em all -,.+*1:\" XXX", Flag: "User", Expected: "gotta catch em all -,.+*1:"},
		// Check for expecting int
		{Input: "XXX: Value=123 XXX", Flag: "Value", Expected: "123"},
		// Check for expecting int as string
		{Input: "XXX: Value=\"123\" XXX", Flag: "Value", Expected: "123"},
		// Check for empty values
		{Input: "XXX: User=", Flag: "User", Expected: ""},
		{Input: "XXX: User= ", Flag: "User", Expected: ""},
		// Check flag as is
		{Input: "--flag", Flag: "--flag", Expected: "--flag"},
		{Input: " --flag", Flag: "--flag", Expected: "--flag"},
		{Input: "	--flag", Flag: "--flag", Expected: "--flag"},
		{Input: "--flag ", Flag: "--flag", Expected: "--flag"},
		{Input: "--flag		", Flag: "--flag", Expected: "--flag"},
		{Input: "XXX --flag AAA XXX", Flag: "--flag", Expected: "AAA"},
		{Input: "XXX --AAA BBB", Flag: "XXX", Expected: "XXX"},
		{Input: "XXX", Flag: "XXX", Expected: "XXX"},
		{Input: "CCC XXX AAA BBB", Flag: "XXX", Expected: "AAA"},
		// Check not false-positive results
		{Input: "YXXX", Flag: "XXX", Expected: ""},
		{Input: "XXXY", Flag: "XXX", Expected: ""},
		// Check for not catching flags that only contains partial flag
		{Input: "XXX: someJunkUser=root XXX", Flag: "Junk", Expected: ""},
		{Input: "XXX: someJunkUser =root XXX", Flag: "User", Expected: ""},
		{Input: "XXX: someJunkUser= root XXX", Flag: "User", Expected: ""},
		{Input: "XXX: someJunkUser = root XXX", Flag: "User", Expected: ""},
		{Input: "XXX: someJunkUser root XXX", Flag: "User", Expected: ""},
		// Check for junk and valid flags at the same time
		{Input: "XXX: someJunkUser User root XXX", Flag: "User", Expected: "root"},
	}

	for i, test := range tests {

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			actual := getFlagValue(test.Input, test.Flag)
			if test.Expected != actual {
				t.Errorf("test %d fail: expected: %v actual: %v\ntest details: %+v\n", i, test.Expected, actual, test)
			}
		})
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
		auditCommandOutput string
		expectedResult     bool
		testWithMultiple   bool
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

	for i, c := range cases {
		res := ts.Execute(c.auditCommandOutput, string(i), c.testWithMultiple)
		if res.TestResult != c.expectedResult {
			t.Errorf("expected:%v, got:%v\n", c.expectedResult, res.TestResult)
		}
	}
}

func Test_toNumeric(t *testing.T) {

	cases := []struct {
		a              string
		b              string
		equal          bool
		expectedToFail bool
	}{
		// tab prefix
		{
			a:     "\t24",
			b:     "24",
			equal: true,
		},
		{
			a:     "24",
			b:     "\t24",
			equal: true,
		},
		{
			a:     "\t24",
			b:     "\t24",
			equal: true,
		},
		{
			a:     "\t24",
			b:     "25",
			equal: false,
		},
		{
			a:     "24",
			b:     "\t25",
			equal: false,
		},
		{
			a:     "\t24",
			b:     "\t25",
			equal: false,
		},

		// tab suffix
		{
			a:     "24\t",
			b:     "24",
			equal: true,
		},
		{
			a:     "24",
			b:     "24\t",
			equal: true,
		},
		{
			a:     "24\t",
			b:     "24\t",
			equal: true,
		},
		{
			a:     "24\t",
			b:     "25",
			equal: false,
		},
		{
			a:     "24",
			b:     "25\t",
			equal: false,
		},
		{
			a:     "24\t",
			b:     "25\t",
			equal: false,
		},

		// space
		{
			a:     "24 ",
			b:     "24",
			equal: true,
		},
		{
			a:     "24",
			b:     "24 ",
			equal: true,
		},
		{
			a:     "24 ",
			b:     "24 ",
			equal: true,
		},
		{
			a:     "24 ",
			b:     "25",
			equal: false,
		},
		{
			a:     "24",
			b:     "25 ",
			equal: false,
		},
		{
			a:     "24 ",
			b:     "25 ",
			equal: false,
		},

		// *nix new line
		{
			a:     "24\n",
			b:     "24",
			equal: true,
		},
		{
			a:     "24",
			b:     "24\n",
			equal: true,
		},
		{
			a:     "24\n",
			b:     "24\n",
			equal: true,
		},
		{
			a:     "24\n",
			b:     "25",
			equal: false,
		},
		{
			a:     "24",
			b:     "25\n",
			equal: false,
		},
		{
			a:     "24\n",
			b:     "25\n",
			equal: false,
		},

		// Windows return char
		{
			a:     "24\r",
			b:     "24",
			equal: true,
		},
		{
			a:     "24",
			b:     "24\r",
			equal: true,
		},
		{
			a:     "24\r",
			b:     "24\r",
			equal: true,
		},
		{
			a:     "24\r",
			b:     "25",
			equal: false,
		},
		{
			a:     "24",
			b:     "25\r",
			equal: false,
		},
		{
			a:     "24\r",
			b:     "25\r",
			equal: false,
		},

		// Expected failures
		{
			a:              "a",
			b:              "25\r",
			expectedToFail: true,
			equal:          false,
		},
		{
			a:              "a",
			b:              "b",
			expectedToFail: true,
			equal:          false,
		},
	}

	for _, c := range cases {
		ar, br, err := toNumeric(c.a, c.b)

		if c.expectedToFail {
			if err == nil {
				t.Errorf("Expected error but instead got none\n")
			}
			continue
		} else if err != nil {
			t.Errorf("Unexpected error: %v\n", err)
			continue
		}

		if c.equal {
			if ar != br {
				t.Errorf("expected a:%q and b:%q to be equal\n", c.a, c.b)
			}
		} else {
			if ar == br {
				t.Errorf("expected a:%q and b:%q NOT to be equal\n", c.a, c.b)
			}
		}
	}
}

func TestCompareOp(t *testing.T) {
	cases := []struct {
		label                 string
		op                    string
		flagVal               string
		compareValue          string
		expectedResultPattern string
		testResult            bool
		expectedToFail        bool
	}{
		// Test Op not matching
		{label: "empty - op", op: "", flagVal: "", compareValue: "", expectedResultPattern: "", testResult: false},
		{label: "op=blah", op: "blah", flagVal: "foo", compareValue: "bar", expectedResultPattern: "", testResult: false},

		// Test Op "eq"
		{label: "op=eq, both empty", op: "eq", flagVal: "", compareValue: "", expectedResultPattern: "No output", testResult: true},

		{label: "op=eq, true==true", op: "eq", flagVal: "true",
			compareValue:          "true",
			expectedResultPattern: "'true' is equal to 'true'",
			testResult:            true},

		{label: "op=eq, false==false", op: "eq", flagVal: "false",
			compareValue:          "false",
			expectedResultPattern: "'false' is equal to 'false'",
			testResult:            true},

		{label: "op=eq, false==true", op: "eq", flagVal: "false",
			compareValue:          "true",
			expectedResultPattern: "'false' is equal to 'true'",
			testResult:            false},

		{label: "op=eq, strings match", op: "eq", flagVal: "KubeletConfiguration",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'KubeletConfiguration' is equal to 'KubeletConfiguration'",
			testResult:            true},

		{label: "op=eq, flagVal=empty", op: "eq", flagVal: "",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'' is equal to 'KubeletConfiguration'",
			testResult:            false},

		{label: "op=eq, compareValue=empty", op: "eq", flagVal: "KubeletConfiguration",
			compareValue:          "",
			expectedResultPattern: "'KubeletConfiguration' is equal to ''",
			testResult:            false},

		// Test Op "noteq"
		{label: "op=noteq, both empty", op: "noteq", flagVal: "",
			compareValue: "", expectedResultPattern: "'' is not equal to ''",
			testResult: false},

		{label: "op=noteq, true!=true", op: "noteq", flagVal: "true",
			compareValue:          "true",
			expectedResultPattern: "'true' is not equal to 'true'",
			testResult:            false},

		{label: "op=noteq, false!=false", op: "noteq", flagVal: "false",
			compareValue:          "false",
			expectedResultPattern: "'false' is not equal to 'false'",
			testResult:            false},

		{label: "op=noteq, false!=true", op: "noteq", flagVal: "false",
			compareValue:          "true",
			expectedResultPattern: "'false' is not equal to 'true'",
			testResult:            true},

		{label: "op=noteq, strings match", op: "noteq", flagVal: "KubeletConfiguration",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'KubeletConfiguration' is not equal to 'KubeletConfiguration'",
			testResult:            false},

		{label: "op=noteq, flagVal=empty", op: "noteq", flagVal: "",
			compareValue:          "KubeletConfiguration",
			expectedResultPattern: "'' is not equal to 'KubeletConfiguration'",
			testResult:            true},

		{label: "op=noteq, compareValue=empty", op: "noteq", flagVal: "KubeletConfiguration",
			compareValue:          "",
			expectedResultPattern: "'KubeletConfiguration' is not equal to ''",
			testResult:            true},

		// Test Op "gt"
		{label: "op=gt, both empty", op: "gt", flagVal: "",
			compareValue: "", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},
		{label: "op=gt, 0 > 0", op: "gt", flagVal: "0",
			compareValue: "0", expectedResultPattern: "0 is greater than 0",
			testResult: false},
		{label: "op=gt, 4 > 5", op: "gt", flagVal: "4",
			compareValue: "5", expectedResultPattern: "4 is greater than 5",
			testResult: false},
		{label: "op=gt, 5 > 4", op: "gt", flagVal: "5",
			compareValue: "4", expectedResultPattern: "5 is greater than 4",
			testResult: true},
		{label: "op=gt, 5 > 5", op: "gt", flagVal: "5",
			compareValue: "5", expectedResultPattern: "5 is greater than 5",
			testResult: false},
		{label: "op=gt, b > 5", op: "gt", flagVal: "b",
			compareValue: "5", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},
		{label: "op=gt, a > b", op: "gt", flagVal: "a",
			compareValue: "b", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},

		// Test Op "lt"
		{label: "op=lt, both empty", op: "lt", flagVal: "",
			compareValue: "", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: true, expectedToFail: true},
		{label: "op=ltt, 0 < 0", op: "lt", flagVal: "0",
			compareValue: "0", expectedResultPattern: "0 is lower than 0",
			testResult: false},
		{label: "op=lt, 4 < 5", op: "lt", flagVal: "4",
			compareValue: "5", expectedResultPattern: "4 is lower than 5",
			testResult: true},
		{label: "op=lt, 5 < 4", op: "lt", flagVal: "5",
			compareValue: "4", expectedResultPattern: "5 is lower than 4",
			testResult: false},
		{label: "op=lt, 5 < 5", op: "lt", flagVal: "5",
			compareValue: "5", expectedResultPattern: "5 is lower than 5",
			testResult: false},
		{label: "op=lt, b < 5", op: "lt", flagVal: "b",
			compareValue: "5", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},
		{label: "op=lt, a < b", op: "lt", flagVal: "a",
			compareValue: "b", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},

		// Test Op "gte"
		{label: "op=gte, both empty", op: "gte", flagVal: "",
			compareValue: "", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: true, expectedToFail: true},
		{label: "op=gte, 0 >= 0", op: "gte", flagVal: "0",
			compareValue: "0", expectedResultPattern: "0 is greater or equal to 0",
			testResult: true},
		{label: "op=gte, 4 >= 5", op: "gte", flagVal: "4",
			compareValue: "5", expectedResultPattern: "4 is greater or equal to 5",
			testResult: false},
		{label: "op=gte, 5 >= 4", op: "gte", flagVal: "5",
			compareValue: "4", expectedResultPattern: "5 is greater or equal to 4",
			testResult: true},
		{label: "op=gte, 5 >= 5", op: "gte", flagVal: "5",
			compareValue: "5", expectedResultPattern: "5 is greater or equal to 5",
			testResult: true},
		{label: "op=gte, b >= 5", op: "gte", flagVal: "b",
			compareValue: "5", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},
		{label: "op=gte, a >= b", op: "gte", flagVal: "a",
			compareValue: "b", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},

		// Test Op "lte"
		{label: "op=lte, both empty", op: "lte", flagVal: "",
			compareValue: "", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: true, expectedToFail: true},
		{label: "op=lte, 0 <= 0", op: "lte", flagVal: "0",
			compareValue: "0", expectedResultPattern: "0 is lower or equal to 0",
			testResult: true},
		{label: "op=lte, 4 <= 5", op: "lte", flagVal: "4",
			compareValue: "5", expectedResultPattern: "4 is lower or equal to 5",
			testResult: true},
		{label: "op=lte, 5 <= 4", op: "lte", flagVal: "5",
			compareValue: "4", expectedResultPattern: "5 is lower or equal to 4",
			testResult: false},
		{label: "op=lte, 5 <= 5", op: "lte", flagVal: "5",
			compareValue: "5", expectedResultPattern: "5 is lower or equal to 5",
			testResult: true},
		{label: "op=lte, b <= 5", op: "lte", flagVal: "b",
			compareValue: "5", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},
		{label: "op=lte, a <= b", op: "lte", flagVal: "a",
			compareValue: "b", expectedResultPattern: "Invalid Number(s) used for comparison",
			testResult: false, expectedToFail: true},

		// Test Op "has"
		{label: "op=gt, both empty", op: "has", flagVal: "",
			compareValue: "", expectedResultPattern: "'' has ''",
			testResult: true},
		{label: "op=gt, flagVal=empty", op: "has", flagVal: "",
			compareValue: "blah", expectedResultPattern: "'' has 'blah'",
			testResult: false},
		{label: "op=gt, compareValue=empty", op: "has", flagVal: "blah",
			compareValue: "", expectedResultPattern: "'blah' has ''",
			testResult: true},
		{label: "op=gt, 'blah' has 'la'", op: "has", flagVal: "blah",
			compareValue: "la", expectedResultPattern: "'blah' has 'la'",
			testResult: true},
		{label: "op=gt, 'blah' has 'LA'", op: "has", flagVal: "blah",
			compareValue: "LA", expectedResultPattern: "'blah' has 'LA'",
			testResult: false},
		{label: "op=gt, 'blah' has 'lo'", op: "has", flagVal: "blah",
			compareValue: "lo", expectedResultPattern: "'blah' has 'lo'",
			testResult: false},

		// Test Op "nothave"
		{label: "op=nothave, both empty", op: "nothave", flagVal: "",
			compareValue: "", expectedResultPattern: " '' does not have ''",
			testResult: false},
		{label: "op=nothave, flagVal=empty", op: "nothave", flagVal: "",
			compareValue: "blah", expectedResultPattern: " '' does not have 'blah'",
			testResult: true},
		{label: "op=nothave, compareValue=empty", op: "nothave", flagVal: "blah",
			compareValue: "", expectedResultPattern: " 'blah' does not have ''",
			testResult: false},
		{label: "op=nothave, 'blah' not have 'la'", op: "nothave", flagVal: "blah",
			compareValue: "la", expectedResultPattern: " 'blah' does not have 'la'",
			testResult: false},
		{label: "op=nothave, 'blah' not have 'LA'", op: "nothave", flagVal: "blah",
			compareValue: "LA", expectedResultPattern: " 'blah' does not have 'LA'",
			testResult: true},
		{label: "op=nothave, 'blah' not have 'lo'", op: "nothave", flagVal: "blah",
			compareValue: "lo", expectedResultPattern: " 'blah' does not have 'lo'",
			testResult: true},

		// Test Op "regex"
		{label: "op=regex, both empty", op: "regex", flagVal: "",
			compareValue: "", expectedResultPattern: " '' matched by ''",
			testResult: true},
		{label: "op=regex, flagVal=empty", op: "regex", flagVal: "",
			compareValue: "blah", expectedResultPattern: " '' matched by 'blah'",
			testResult: false},

		// Test Op "valid_elements"
		{label: "op=valid_elements, valid_elements both empty", op: "valid_elements", flagVal: "",
			compareValue: "", expectedResultPattern: "'' contains valid elements from ''",
			testResult: true},

		{label: "op=valid_elements, valid_elements flagVal empty", op: "valid_elements", flagVal: "",
			compareValue: "a,b", expectedResultPattern: "'' contains valid elements from 'a,b'",
			testResult: false},

		{label: "op=valid_elements, valid_elements expectedResultPattern empty", op: "valid_elements", flagVal: "a,b",
			compareValue: "", expectedResultPattern: "'a,b' contains valid elements from ''",
			testResult: false},

		// Test Op "bitmask"
		{label: "op=bitmask, 644 AND 640", op: "bitmask", flagVal: "640",
			compareValue: "644", expectedResultPattern: "bitmask '640' AND '644'",
			testResult: true},
		{label: "op=bitmask, 644 AND 777", op: "bitmask", flagVal: "777",
			compareValue: "644", expectedResultPattern: "bitmask '777' AND '644'",
			testResult: false},
		{label: "op=bitmask, 644 AND 444", op: "bitmask", flagVal: "444",
			compareValue: "644", expectedResultPattern: "bitmask '444' AND '644'",
			testResult: true},
		{label: "op=bitmask, 644 AND 211", op: "bitmask", flagVal: "211",
			compareValue: "644", expectedResultPattern: "bitmask '211' AND '644'",
			testResult: false},
		{label: "op=bitmask, ACDC AND 211", op: "bitmask", flagVal: "ACDC",
			compareValue: "644", expectedResultPattern: "Invalid Number(s) used for bitmask",
			testResult: false},
		{label: "op=bitmask, 644 AND Nirvana", op: "bitmask", flagVal: "211",
			compareValue: "Nirvana", expectedResultPattern: "Invalid Number(s) used for bitmask",
			testResult: false},
	}

	for _, c := range cases {
		testResult, expectedResultPattern, err := compareOp(c.op, c.flagVal, c.compareValue)
		if c.expectedToFail {
			if err == nil {
				t.Errorf("Expected error for %s, but instead got none", c.label)
			}
			if expectedResultPattern != c.expectedResultPattern {
				t.Errorf("'expectedResultPattern' did not match - label: %q op: %q expected 'expectedResultPattern':%q  got:%q\n", c.label, c.op, c.expectedResultPattern, expectedResultPattern)
			}
			continue
		}

		if expectedResultPattern != c.expectedResultPattern {
			t.Errorf("'expectedResultPattern' did not match - label: %q op: %q expected 'expectedResultPattern':%q  got:%q\n", c.label, c.op, c.expectedResultPattern, expectedResultPattern)
		}

		if testResult != c.testResult {
			t.Errorf("'testResult' did not match - label: %q op: %q expected 'testResult':%t  got:%t\n", c.label, c.op, c.testResult, testResult)
		}
	}
}

func TestAllElementsValid(t *testing.T) {
	cases := []struct {
		source []string
		target []string
		valid  bool
	}{
		{
			source: []string{},
			target: []string{},
			valid:  true,
		},
		{
			source: []string{"blah"},
			target: []string{},
			valid:  false,
		},
		{
			source: []string{},
			target: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
			valid: false,
		},
		{
			source: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			target: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
			valid: true,
		},
		{
			source: []string{"blah"},
			target: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
			valid: false,
		},
		{
			source: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "blah"},
			target: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
			valid: false,
		},
	}
	for _, c := range cases {
		if !allElementsValid(c.source, c.target) && c.valid {
			t.Errorf("Not All Elements in %q are found in %q \n", c.source, c.target)
		}
	}
}

func TestSplitAndRemoveLastSeparator(t *testing.T) {
	cases := []struct {
		source     string
		valid      bool
		elementCnt int
	}{
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256",
			valid:      true,
			elementCnt: 8,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ",
			valid:      true,
			elementCnt: 2,
		},
		{
			source:     " TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,",
			valid:      true,
			elementCnt: 2,
		},
	}

	for _, c := range cases {
		as := splitAndRemoveLastSeparator(c.source, defaultArraySeparator)
		if len(as) == 0 && c.valid {
			t.Errorf("Split did not work with %q \n", c.source)
		}

		if c.elementCnt != len(as) {
			t.Errorf("Split did not work with %q expected: %d got: %d\n", c.source, c.elementCnt, len(as))
		}

	}
}
func TestTestUnmarshal(t *testing.T) {
	type kubeletConfig struct {
		Kind       string
		APIVersion string
		Address    string
	}
	cases := []struct {
		content        string
		jsonInterface  interface{}
		expectedToFail bool
	}{
		{
			`{
			"kind": "KubeletConfiguration",
			"apiVersion": "kubelet.config.k8s.io/v1beta1",
			"address": "0.0.0.0"
			}
			`,
			kubeletConfig{},
			false,
		}, {
			`
kind: KubeletConfiguration
address: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
  enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
`,
			kubeletConfig{},
			false,
		},
		{
			`
kind: ddress: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta
`,
			kubeletConfig{},
			true,
		},
	}

	for _, c := range cases {
		err := unmarshal(c.content, &c.jsonInterface)
		if err != nil {
			if !c.expectedToFail {
				t.Errorf("%s, expectedToFail:%v, got:%v\n", c.content, c.expectedToFail, err)
			}
		} else {
			if c.expectedToFail {
				t.Errorf("%s, expectedToFail:%v, got:Did not fail\n", c.content, c.expectedToFail)
			}
		}
	}
}

func TestExecuteJSONPath(t *testing.T) {
	type kubeletConfig struct {
		Kind       string
		APIVersion string
		Address    string
	}
	cases := []struct {
		jsonPath       string
		jsonInterface  kubeletConfig
		expectedResult string
		expectedToFail bool
	}{
		{
			// JSONPath parse works, results don't match
			"{.Kind}",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				APIVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"blah",
			true,
		},
		{
			// JSONPath parse works, results match
			"{.Kind}",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				APIVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"KubeletConfiguration",
			false,
		},
		{
			// JSONPath parse fails
			"{.ApiVersion",
			kubeletConfig{
				Kind:       "KubeletConfiguration",
				APIVersion: "kubelet.config.k8s.io/v1beta1",
				Address:    "127.0.0.0",
			},
			"",
			true,
		},
	}
	for _, c := range cases {
		result, err := executeJSONPath(c.jsonPath, c.jsonInterface)
		if err != nil && !c.expectedToFail {
			t.Fatalf("jsonPath:%q, expectedResult:%q got:%v\n", c.jsonPath, c.expectedResult, err)
		}
		if c.expectedResult != result && !c.expectedToFail {
			t.Errorf("jsonPath:%q, expectedResult:%q got:%q\n", c.jsonPath, c.expectedResult, result)
		}
	}
}
