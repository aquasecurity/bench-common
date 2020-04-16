package check

import (
	"strings"
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
		{
			// Should match if there are no constraints on the test at all
			Expected: true,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{},
						Remediation: "Expected",
					},
				},
			},
		},
		{
			// Should not match if there are constraints on the test that aren't defined for this run
			Expected: false,
			SubChecks: []*SubCheck{
				{
					BaseCheck{
						Constraints: map[string][]string{"something": []string{"not", "defined"}},
						Remediation: "Expected",
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
func TestTextToCommand(t *testing.T) {
	type TestCase struct {
		auditCommand          string
		expectedSlicedCommand []string
	}

	// For each test case, we want get the different commands separated by | and exclude the \\|
	// which stand for the use of | as OR operator and not as a pipe.
	testCases := []TestCase{
		{
			// Test for mixed case of pipeline and or cases
			auditCommand: "grep -E -i \"(\\\\v\\|\\\\r\\|\\\\m\\|\\\\s)\\|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd",
			expectedSlicedCommand: []string{
				"grep -E -i \"(\\\\v|\\\\r|\\\\m|\\\\s)|$(grep '^ID=' /etc/os-release",
				"cut -d= -f2",
				"sed -e 's/\"//g'))\" /etc/motd"},
		},
		{
			// Test for regular pipe
			auditCommand: "lsmod | grep cramfs",
			expectedSlicedCommand: []string{
				"lsmod",
				"grep cramfs"},
		},
		{
			// Test for | as Or
			auditCommand: "grep -E \"^(server\\|pool)\" /etc/ntp.conf",
			expectedSlicedCommand: []string{
				"grep -E \"^(server|pool)\" /etc/ntp.conf"},
		},
	}
	for i, testCase := range testCases {
		commands := textToCommand(testCase.auditCommand)
		for j, command := range commands {
			testSlicedCommand := strings.Join(command.Args[:], " ")
			if testSlicedCommand != testCase.expectedSlicedCommand[j] {
				t.Errorf("case %d expected:%v, got:%v\n", i, testCase.expectedSlicedCommand[j], testSlicedCommand)
			}
		}
	}
}
func TestIsShellCommand(t *testing.T) {
	type TestCase struct {
		command  string
		Expected bool
	}

	// For each test case, we want to find the first subcheck that matches the constraints in testDefinedConstraints
	testCases := []TestCase{
		{
			// Exist command
			command:  "/bin/grep",
			Expected: true,
		},
		{
			// Non exist command
			command:  "/bin/nonExistCommand",
			Expected: false,
		},
	}
	for ii, testCase := range testCases {
		if isShellCommand(testCase.command) != testCase.Expected {
			t.Errorf("case %d expected for isShellCommand(\"%v\") to return: %v\n", ii, testCase.command, testCase.Expected)
		}
	}

}
