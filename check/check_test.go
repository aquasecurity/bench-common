package check

import (
	"testing"

	"github.com/aquasecurity/bench-common/auditeval"
	yaml "gopkg.in/yaml.v2"
)

// For the tests, say that we are running on an ubuntu system using the grub bootloader
var testDefinedConstraints = map[string][]string{"platform": {"ubuntu"}, "boot": {"grub"}}

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
		Expected  bool
	}

	// For each test case, we want to find the first subcheck that matches the constraints in testDefinedConstraints
	testCases := []TestCase{
		{
			// Expect to find the first test because it matches ubuntu
			Expected: true,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}},
						Remediation: "Expected",
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"rhel"}},
						Remediation: "Not expected",
					},
				},
			},
		},
		{
			// Expect to find the second test because it matches ubuntu
			Expected: true,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"rhel"}},
						Remediation: "Not expected",
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}},
						Remediation: "Expected",
					},
				},
			},
		},
		{
			// Expect to find the second test because it matches ubuntu and grub
			Expected: true,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"rhel"}},
						Remediation: "Not expected",
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}, "boot": []string{"grub"}},
						Remediation: "Expected",
					},
				},
			},
		},
		{
			// Expect to find the second test because it matches ubuntu and grub
			Expected: true,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"rhel"}},
						Remediation: "Not expected",
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}, "boot": []string{"grub", "also valid for something else"}},
						Remediation: "Expected",
					},
				},
			},
		},
		{
			Expected: false,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"rhel", "another"}},
						Remediation: "Not expected",
					},
				},
				{
					BaseCheck{
						Constraints: map[string][]string{"platform": []string{"ubuntu"}, "boot": []string{"another"}},
						Remediation: "Not expected",
					},
				},
			},
		},
	}

	for ii, testCase := range testCases {
		chosen := getFirstValidSubCheck(testCase.SubChecks, testDefinedConstraints)
		if !testCase.Expected {
			if chosen != nil {
				t.Errorf("case %d didn't expect to find a matching case: %v\n", ii, chosen)
			}
		} else {
			if chosen == nil {
				t.Errorf("case %d expected to find a match but didn't", ii)
			} else {
				if chosen.Remediation != "Expected" {
					t.Errorf("case %d unexpected test selected: actual: %v\n", ii, chosen)
				}
			}
		}
	}
}
