package check

import (
	"reflect"
	"testing"
)

var testDefinedConstraints = map[string][]string{"platform": {"ubuntu", "rhel"}, "boot": {"grub"}}

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{check: Check{Type: "manual"}, Expected: WARN},
		{check: Check{Type: "skip"}, Expected: INFO},
		{check: Check{Type: "", Scored: false}, Expected: WARN}, // Not scored checks with no type should be marked warn
		{check: Check{Type: "", Scored: true}, Expected: WARN},  // If there are no tests in the check, warn
	}

	for _, testCase := range testCases {

		testCase.check.Run(testDefinedConstraints)

		if testCase.check.State != testCase.Expected {
			t.Errorf("test failed, expected %s, actual %s\n", testCase.Expected, testCase.check.State)
		}
	}
}

func TestGetFirstValidSubCheck(t *testing.T) {
	type TestCase struct {
		SubChecks []SubCheck
		Chosen    *BaseCheck
		Expected  *BaseCheck
	}

	testCases := []TestCase{
		{
			SubChecks: []SubCheck{
				{
					BaseCheck{
						Audit:       "ls /home | grep $USER",
						Constraints: map[string][]string{"platform": []string{"ubuntu"}},
						Remediation: "Fake test, check that current user has home directory",
					},
				},
				{
					BaseCheck{
						Audit:       "ls /home | grep $USER",
						Constraints: map[string][]string{"platform": []string{"Fail", "ubuntu", "grub"}},
						Remediation: "Fake test, check that current user has home directory",
					},
				},
			},
			Expected: &BaseCheck{
				Audit:       "ls /home | grep $USER",
				Constraints: map[string][]string{"platform": []string{"ubuntu"}},
				Remediation: "Fake test, check that current user has home directory",
			},
		},
		{
			SubChecks: []SubCheck{
				{
					BaseCheck{
						Audit:       "ls /home | grep $USER",
						Constraints: map[string][]string{"platform": []string{"ubuntu", "p"}},
						Remediation: "Fake test, check that current user has home directory",
					},
				},
				{
					BaseCheck{
						Audit:       "ls /home | grep $USER",
						Constraints: map[string][]string{"platform": []string{"Fail", "ubuntu", "grub"}},
						Remediation: "Fake test, check that current user has home directory",
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
