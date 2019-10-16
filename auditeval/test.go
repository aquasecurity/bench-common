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

	"github.com/golang/glog"
)

type binOp string

const (
	and binOp = "and"
	or        = "or"
)

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
	TestResult     bool
	ActualResult   string
	ExpectedResult string
}

func (t *testItem) execute(s string, isMultipleOutput bool) (result testOutput, err error) {
	s = strings.TrimRight(s, " \n")

	// If the test has output that should be evaluated for each row
	// For example - checking that no container is in privileged mode - docker ps and than checking for each container
	if isMultipleOutput {
		output := strings.Split(s, "\n")

		for _, op := range output {
			result.TestResult, result.ExpectedResult, err = t.evaluate(op)

			// If the test failed for the current row, no need to keep testing for this output
			if !result.TestResult {
				break
			}
		}
	} else {
		result.TestResult, result.ExpectedResult, err = t.evaluate(s)
	}

	return result, err
}

// Tests combine test items with binary operations to evaluate results.
type Tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

func (ts *Tests) Execute(s, testId string, isMultipleOutput bool) *testOutput {
	finalOutput := &testOutput{}
	var result bool
	var err error

	if ts == nil {
		return finalOutput
	}

	res := make([]testOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	for i, t := range ts.TestItems {
		res[i], err = t.execute(s, isMultipleOutput)
		if err != nil {
			glog.V(2).Infof("Failed running test %s. %s", testId, err)
		}
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
			finalOutput.ExpectedResult += fmt.Sprintf("%s AND ", res[i].ExpectedResult)
		}

		// Delete last iteration ' AND '
		finalOutput.ExpectedResult = finalOutput.ExpectedResult[:len(finalOutput.ExpectedResult)-5]
	case or:
		result = false
		for i := range res {
			result = result || res[i].TestResult
			finalOutput.ExpectedResult += fmt.Sprintf("%s OR ", res[i].ExpectedResult)
		}

		// Delete last iteration ' OR '
		finalOutput.ExpectedResult = finalOutput.ExpectedResult[:len(finalOutput.ExpectedResult)-4]
	}

	finalOutput.TestResult = result
	finalOutput.ActualResult = s
	return finalOutput
}

func toNumeric(a, b string) (c, d int, err error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)

	if len(a) == 0 || len(b) == 0 {
		return -1, -1, fmt.Errorf("cannot convert blank value to numeric")
	}
	c, err = strconv.Atoi(a)
	if err != nil {
		return c, d, fmt.Errorf("failed converting %s to integer, %s", a, err)
	}
	d, err = strconv.Atoi(b)
	if err != nil {
		if err != nil {
			return c, d, fmt.Errorf("failed converting %s to integer, %s", b, err)
		}
	}

	return c, d, nil
}

func getFlagValue(s, flag string) string {
	if flag == "" {
		return s
	}

	var flagVal string
	pttns := []string{
		flag + `\s*=\s*"(.*)"`,
		flag + `\s*=([^ \n]*)`,
		flag + `\s+([^-\s]+)`,
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

func (t *testItem) evaluate(output string) (TestResult bool, ExpectedResult string, err error) {

	if t.Set {
		if t.Compare.Op != "" {
			flagVal := getFlagValue(output, t.Flag)
			expectedResultPattern := ""
			var a, b int

			switch t.Compare.Op {
			case "eq":
				expectedResultPattern = "'%s' Is equal to '%s'"
				value := strings.ToLower(flagVal)
				// In case the result should be empty, changing the status to indicate "No output"
				if t.Compare.Value == "" && t.Flag == "" {
					expectedResultPattern = "%s%sNo output"
				}
				// Do case insensitive comparison for booleans ...
				if value == "false" || value == "true" {
					TestResult = value == t.Compare.Value
				} else {
					TestResult = flagVal == t.Compare.Value
				}

			case "noteq":
				expectedResultPattern = "'%s' Is not equal to '%s'"
				value := strings.ToLower(flagVal)
				// Do case insensitive comparaison for booleans ...
				if value == "false" || value == "true" {
					TestResult = !(value == t.Compare.Value)
				} else {
					TestResult = !(flagVal == t.Compare.Value)
				}

			case "gt":
				expectedResultPattern = "%s Is greater then %s"
				a, b, err = toNumeric(flagVal, t.Compare.Value)
				if err == nil {
					TestResult = a > b
				}

			case "gte":
				expectedResultPattern = "%s Is greater or equal to %s"
				a, b, err = toNumeric(flagVal, t.Compare.Value)
				if err == nil {
					TestResult = a >= b
				}

			case "lt":
				expectedResultPattern = "%s Is lower then %s"
				a, b, err = toNumeric(flagVal, t.Compare.Value)
				if err == nil {
					TestResult = a < b
				}

			case "lte":
				expectedResultPattern = "%s Is lower or equal to %s"
				a, b, err = toNumeric(flagVal, t.Compare.Value)
				if err == nil {
					TestResult = a <= b
				}

			case "has":
				expectedResultPattern = "'%s' Has '%s'"
				TestResult = strings.Contains(flagVal, t.Compare.Value)

			case "nothave":
				expectedResultPattern = " '%s' Not have '%s'"
				TestResult = !strings.Contains(flagVal, t.Compare.Value)
			}

			ExpectedResult = fmt.Sprintf(expectedResultPattern, t.Flag, t.Compare.Value)
		} else {
			ExpectedResult = fmt.Sprintf("'%s' Is present", t.Flag)
			TestResult, _ = regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, output)
		}
	} else {
		ExpectedResult = fmt.Sprintf("'%s' Is not present", t.Flag)
		r, _ := regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, output)
		TestResult = !r
	}

	return TestResult, ExpectedResult, err
}
