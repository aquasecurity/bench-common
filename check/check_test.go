package check

import (
	"github.com/aquasecurity/bench-common/auditeval"
	yaml "gopkg.in/yaml.v2"
	"reflect"
	"testing"
)

var testDefinedConstraints = map[string][]string{"platform": {"ubuntu", "rhel"}, "boot": {"grub"}}

const def1 = `
---
tests:
bin_op: or
test_items:
- flag: "root"
  set: true
`

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		check    Check
		Expected State
	}

	ts := new(auditeval.Tests)
	if err := yaml.Unmarshal([]byte(def1), ts); err != nil {
		t.Fatalf("error unmarshaling tests yaml %v", err)
	}

	checkTypeManual := Check{Type: "manual", Tests: ts, Scored: true, auditer: Audit("ps -ef")}
	checkTypeSkip := Check{Type: "skip", Tests: ts, Scored: true, auditer: Audit("ps -ef")}
	checkNotScored := Check{Type: "", Tests: ts, Scored: false, auditer: Audit("ps -ef")}
	checkNoTests := Check{Type: "", Scored: true, auditer: Audit("")}

	testCases := []TestCase{
		{check: checkTypeManual, Expected: WARN},
		{check: checkTypeSkip, Expected: INFO},
		{check: checkNotScored, Expected: WARN}, // Not scored checks with no type should be marked warn
		{check: checkNoTests, Expected: WARN},   // If there are no tests in the check, warn
	}

	for i, testCase := range testCases {

		testCase.check.Run(testDefinedConstraints)

		if testCase.check.State != testCase.Expected {
			t.Errorf("test failed - number %d, expected %s, actual %s\n", i, testCase.Expected, testCase.check.State)
		}
	}
}

func TestGetFirstValidSubCheck(t *testing.T) {
	type TestCase struct {
		SubChecks []*SubCheck
		Chosen    *BaseCheck
		Expected  *BaseCheck
	}

	testCases := []TestCase{
		{
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}},
						Remediation: "Fake test, check that current user has home directory",
						auditer:     Audit("ls /home | grep $USER"),
					},
				},
				{
					BaseCheck{
						Audit:       "ls /home | grep $USER",
						Constraints: map[string][]string{"platform": []string{"Fail", "ubuntu", "grub"}},
						Remediation: "Fake test, check that current user has home directory",
						auditer:     Audit("ls /home | grep $USER"),
					},
				},
			},
			Expected: &BaseCheck{
				Constraints: map[string][]string{"platform": []string{"ubuntu"}},
				Remediation: "Fake test, check that current user has home directory",
				auditer:     Audit("ls /home | grep $USER"),
			},
		},
		{
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu", "p"}},
						Remediation: "Fake test, check that current user has home directory",
						auditer:     Audit("ls /home | grep $USER"),
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"Fail", "ubuntu", "grub"}},
						Remediation: "Fake test, check that current user has home directory",
						auditer:     Audit("ls /home | grep $USER"),
					},
				},
			},
			Expected: nil,
		},
	}

	for _, testCase := range testCases {
		testCase.Chosen = getFirstValidSubCheck(testCase.SubChecks, testDefinedConstraints)

		if !reflect.DeepEqual(testCase.Chosen, testCase.Expected) {
			t.Errorf("test fail: expected: %v actual: %v\n", testCase.Chosen, testCase.Expected)
		}
	}
}
