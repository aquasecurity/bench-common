package check

import (
	"fmt"
	"strconv"
	"testing"
)

const wrongTypeYaml = `---
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
      audittype: "wrong_type"
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
`
const customTypeYaml = `---
controls:
id: 1
text: "Master Node Security Configuration"
type: "master"
groups:
- id: 1.1
  text: "API Server"
  checks:
    - id: 1.1.1
      text: "Check host IP"
      audittype: "check_ip"
      audit:
         url: https://api.ipify.org?format=json 
      tests:
        test_items:
        - flag: "192.168.1.1"
          set: true
      remediation: "Access allowed from ip 192.168.1.1 only"
      scored: true
`

func TestRegisterAuditType(t *testing.T) {

	bench := NewBench()

	if err := bench.RegisterAuditType(TypeAudit, func() interface{} { return Audit("test") }); err != nil {
		t.Errorf("Failed to register new Audit type")
		return
	}
	if err := bench.RegisterAuditType(TypeAudit, func() interface{} { return Audit("test") }); err == nil {
		t.Errorf("RegisterAuditType should have failed on duplicate types")
		return
	}

}

type ipAuditMock struct {
	URL string
}

func (a ipAuditMock) Execute(customConfig ...interface{}) (result string, errMessage string, state State) {
	//I don't really implement checking ip here, since the goal of this mock to test custom audit type
	return "", "", PASS
}
func TestNewControlsType(t *testing.T) {

	type args struct {
		in           []byte
		definitions  []string
		SubstituFile string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"fail wrong type",
			args{[]byte(wrongTypeYaml), []string{}, ""},
			true},
		{"working correctly type",
			args{[]byte(customTypeYaml), []string{}, ""},
			false},
	}
	b := NewBench()
	b.RegisterAuditType("check_ip", func() interface{} { return &ipAuditMock{} })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.NewControls(tt.args.in, tt.args.definitions, tt.args.SubstituFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("bench.NewControls() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestExtractAllAuditsForDefaultBench(t *testing.T) {

	c, err := NewControls([]byte(def), nil, "")
	if err != nil {
		t.Fatalf("could not create control object: %s", err)
	}

	err = defaultBench.extractAllAudits(c)
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
				if c.Audit == nil && string(audit) == "" { // nothing to check when no audit attribute in check
					continue
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
				if s.Audit == nil && string(audit) == "" { // nothing to check when no audit attribute in check
					continue
				}
				if string(audit) != fmt.Sprintf("%v", s.Audit) {
					t.Errorf("ID %s: extracted audit %s, expected %v", c.ID, string(audit), s.Audit)
				}
			}
		}
	}
}
func TestMultiWordReplace(t *testing.T) {
	cases := []struct {
		input   string
		sub     string
		subname string
		output  string
	}{
		{input: "Here's a file with no substitutions", sub: "blah", subname: "blah", output: "Here's a file with no substitutions"},
		{input: "Here's a file with a substitution", sub: "blah", subname: "substitution", output: "Here's a file with a blah"},
		{input: "Here's a file with multi-word substitutions", sub: "multi word", subname: "multi-word", output: "Here's a file with 'multi word' substitutions"},
		{input: "Here's a file with several several substitutions several", sub: "blah", subname: "several", output: "Here's a file with blah blah substitutions blah"},
	}
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			s := multiWordReplace(c.input, c.subname, c.sub)
			if s != c.output {
				t.Fatalf("Expected %s got %s", c.output, s)
			}
		})
	}
}
