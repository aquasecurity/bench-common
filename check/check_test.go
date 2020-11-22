package check

import (
	"fmt"
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
const def2 = `---
id: 1.1
text: "This is a test test (Scored)"
sub_checks:
- check:
    audit: "anything"
    tests:
      test_items:
      - flag: ""
        compare:
          op: eq
          value: ""
        set: true			  
    remediation: "It should pass :) "
    scored: true
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

	checkSubChecks := new(Check)
	if err := yaml.Unmarshal([]byte(def2), checkSubChecks); err != nil {
		t.Fatalf("error unmarshaling check yaml %v", err)
	}

	checkTypeManual := Check{Type: "manual", Tests: ts, Scored: true, auditer: Audit("ps -ef")}
	checkTypeSkip := Check{Type: "skip", Tests: ts, Scored: true, auditer: Audit("ps -ef")}
	checkNoTests := Check{Type: "", Scored: true, auditer: Audit("")}
	checkScoredFail := Check{Scored: true, Tests: ts, auditer: Audit("echo anything")}
	checkNotScoredFail := Check{Scored: false, Tests: ts, auditer: Audit("echo anything")}

	testCases := []TestCase{
		{check: checkTypeManual, Expected: WARN},
		{check: checkTypeSkip, Expected: INFO},
		{check: checkNoTests, Expected: WARN},       // If there are no tests in the check, warn
		{check: checkScoredFail, Expected: FAIL},    // If scored test fails. FAIL
		{check: checkNotScoredFail, Expected: WARN}, // If not scored test fails, WARN
		{check: *checkSubChecks, Expected: PASS},
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

func Test_runAudit(t *testing.T) {
	type args struct {
		audit  string
		output string
	}
	tests := []struct {
		name   string
		args   args
		errMsg string
		output string
	}{
		{
			name: "run success",
			args: args{
				audit: "echo 'hello world'",
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run multiple lines script",
			args: args{
				audit: `
hello() {
  echo "hello world"
}

hello
`,
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run failed",
			args: args{
				audit: "unknown_command",
			},
			errMsg: "failed to run: \"unknown_command\", output: \"/bin/sh: ",
			output: "not found\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errMsg string
			output, err := runAudit(tt.args.audit)
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != "" && !strings.Contains(errMsg, tt.errMsg) {
				t.Errorf("name %s errMsg = %q, want %q", tt.name, errMsg, tt.errMsg)
			}
			if errMsg == "" && output != tt.output {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
			if errMsg != "" && !strings.Contains(output, tt.output) {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
		})
	}
}

func TestRunAuditCommands(t *testing.T) {

	cases := []struct {
		b   BaseCheck
		s   State
		o   string
		err bool
	}{
		{
			// 0
			b: BaseCheck{auditer: Audit("anything"), Type: "manual"},
			s: "WARN",
		}, {
			// 1
			b: BaseCheck{auditer: Audit("anything"), Type: "skip"},
			s: "INFO",
		}, {
			// 2
			// If the audit command can't be run, we eventually report FAIL but this is done in
			// (c *Check) Run() based on the final output
			b: BaseCheck{auditer: Audit("anything")},
			s: "", err: true, o: "/bin/sh: 1: anything: not found",
		}, {
			// 3
			b: BaseCheck{auditer: Audit("echo hello")},
			o: "hello",
		}, {
			// 4
			b:   BaseCheck{auditer: Audit("echo hello | grep notInOutput")},
			err: true,
		}, {
			// 5
			b: BaseCheck{auditer: Audit("echo hello | grep hel")},
			o: "hello",
		}, {
			// 6
			b: BaseCheck{auditer: Audit("echo $(ls . | grep 'bench')")},
			o: "bench.go bench_test.go",
		}, {
			// 7
			// Like in test #2 the final state will be fail, but currently in runAuditCommands
			// is just an empty string
			b: BaseCheck{auditer: Audit("echo $(ls . | grep 'bench') | anything")},
			s: "", err: true, o: "/bin/sh: 1: anything: not found",
		},
	}

	for i, c := range cases {
		output, errmsg, state := runAuditCommands(c.b)
		if state != c.s {
			t.Errorf("Test %d: expected state %s, got %s", i, c.s, state)
		}
		if strings.TrimSpace(output) != c.o {
			t.Errorf("Test %d: expected output %s, got %s", i, c.o, output)
		}
		if (errmsg != "") && !c.err {
			t.Errorf("Test %d: unexpected errmsg %s", i, errmsg)
		}
		if (errmsg == "") && c.err {
			t.Errorf("Test %d unexpectedly didn't return an error message", i)
		}
		fmt.Printf("output %s, err %s\n", output, errmsg)
	}
}
