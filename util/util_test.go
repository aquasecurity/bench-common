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

func TestMakeSubsitutions(t *testing.T) {
	cases := []struct {
		input string
		subst map[string]string
		exp   string
	}{
		{input: "Replace $thisbin", subst: map[string]string{"this": "that"}, exp: "Replace that"},
		{input: "Replace $thisbin", subst: map[string]string{"this": "that", "here": "there"}, exp: "Replace that"},
		{input: "Replace $thisbin and $herebin", subst: map[string]string{"this": "that", "here": "there"}, exp: "Replace that and there"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			s := MakeSubstitutions(c.input, "bin", c.subst)
			if s != c.exp {
				t.Fatalf("Got %s expected %s", s, c.exp)
			}
		})
	}
}

func TestGetSubstitutionMap(t *testing.T) {
	tests := []struct {
		name         string
		substituData []byte
		want         map[string]string
	}{
		{
			name:         "Test for creating valid map",
			substituData: []byte(subs),
			want:         map[string]string{"docker-storage": "/var/lib/docker", "example": "/exmaple/change"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSubstitutionMap(tt.substituData); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSubstitutionMap() = %v, want %v", got, tt.want)
			}
		})
	}
