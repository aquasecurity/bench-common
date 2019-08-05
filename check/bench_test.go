package check

import (
	"fmt"
	"reflect"
	"testing"
)

const check = `---
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

func TestNewControlsWrongType(t *testing.T) {

	type args struct {
		in          []byte
		definitions []string
	}
	tests := []struct {
		name    string
		args    args
		want    *Controls
		wantErr bool
	}{
		{"create controls test",
			args{[]byte(check), []string{}},
			nil,
			true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &bench{}
			got, err := b.NewControls(tt.args.in, tt.args.definitions)
			if (err != nil) != tt.wantErr {
				t.Errorf("bench.NewControls() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("bench.NewControls() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAllAuditsForDefaultBench(t *testing.T) {

	c, err := NewControls([]byte(def), nil)
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
				if s.Audit != nil && s.Audit != "" {

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
}
