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
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type binOp string

const (
	and binOp = "and"
	or        = "or"
)

// Tests combine test items with binary operations to evaluate results.
type Tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

type testItem struct {
	Flag    string
	Output  string
	Value   string
	Set     bool
	Compare compare
}

type compare struct {
	Op    string
	Value string
}

type testOutput struct {
	TestResult   bool
	ActualResult string
}

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{TestResult: true, ActualResult: ""}
	s = strings.TrimRight(s, " \n")

	// If the test needs to run on multiple values
	values := strings.Split(s, "\n")
	currentResult := false

	for _, v := range values {
		if t.Set {
			if t.Compare.Op != "" {
				flagVal := getFlagValue(v, t.Flag)
				result.ActualResult = strings.ToLower(flagVal)
				currentResult = eval(flagVal, t.Compare.Op, t.Compare.Value)
			} else {
				currentResult, _ = regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, v)
			}
		} else {
			r, _ := regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, v)
			currentResult = !r
		}

		if !currentResult {
			result.TestResult = false
			break
		}
	}

	return result
}

func (ts *Tests) Execute(s string) *testOutput {
	finalOutput := &testOutput{}
	var result bool
	if ts == nil {
		return finalOutput
	}

	res := make([]testOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	for i, t := range ts.TestItems {
		res[i] = *(t.execute(s))
	}

	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		fmt.Fprintf(os.Stderr, "unknown binary operator for tests %s\n", ts.BinOp)
		os.Exit(1)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].TestResult
		}
	case or:
		result = false
		for i := range res {
			result = result || res[i].TestResult
		}
	}
	finalOutput.TestResult = result
	finalOutput.ActualResult = res[0].ActualResult

	return finalOutput
}

func eval(flagVal, compareOp, compareValue string) bool {
	switch compareOp {
	case "eq":
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			return value == compareValue
		} else {
			return flagVal == compareValue
		}

	case "noteq":
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			return !(value == compareValue)
		} else {
			return !(flagVal == compareValue)
		}

	case "gt":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a > b
		}

	case "gte":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a >= b
		}

	case "lt":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a < b
		}

	case "lte":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a <= b
		}

	case "has":
		return strings.Contains(flagVal, compareValue)

	case "nothave":
		return !strings.Contains(flagVal, compareValue)
	}

	return false
}

func toNumeric(a, b string) (c, d int, err error) {
	if len(a) == 0 || len(b) == 0 {
		return -1, -1, fmt.Errorf("Cannot convert blank value to numeric")
	}
	c, err = strconv.Atoi(a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", a, err)
		os.Exit(1)
	}
	d, err = strconv.Atoi(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", b, err)
		os.Exit(1)
	}

	return c, d, err
}

func getFlagValue(s, flag string) string {
	var flagVal string
	pttns := []string{
		flag + `=([^ \n]*)`,
		flag + ` +([^- ]+)`,
		`(?:^| +)` + `(` + flag + `)` + `(?: |$)`,
	}
	for _, pttn := range pttns {
		flagRe := regexp.MustCompile(pttn)
		vals := flagRe.FindStringSubmatch(s)
		for i, currentValue := range vals {
			if i == 0 {
				continue
			}
			if len(currentValue) > 0 {
				flagVal = currentValue
				return flagVal
			}
		}
	}
	return flagVal
}
