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

package util

import (
	"strconv"
	"testing"
)

var g string

func fakeps(proc string) string {
	return g
}
func TestVerifyBin(t *testing.T) {
	cases := []struct {
		proc  string
		psOut string
		exp   bool
	}{
		{proc: "single", psOut: "single", exp: true},
		{proc: "single", psOut: "", exp: false},
		{proc: "two words", psOut: "two words", exp: true},
		{proc: "two words", psOut: "", exp: false},
		{proc: "cmd", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd param1 param2", exp: true},
		{proc: "cmd param", psOut: "cmd", exp: false},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			g = c.psOut
			v := verifyBin(c.proc, fakeps)
			if v != c.exp {
				t.Fatalf("Expected %v got %v", c.exp, v)
			}
		})
	}
}
