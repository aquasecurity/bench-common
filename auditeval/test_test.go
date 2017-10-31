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
		res := ts.Execute(c.str)
		if res != c.want {
			t.Errorf("expected:%v, got:%v\n", c.want, res)
		}
	}
}
