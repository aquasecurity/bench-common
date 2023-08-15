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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/glog"
	yaml "gopkg.in/yaml.v3"
	"k8s.io/client-go/util/jsonpath"
)

type binOp string

const (
	and                   binOp = "and"
	or                          = "or"
	defaultArraySeparator       = ","
)

type testItem struct {
	Flag    string
	Path    string
	Output  string
	Value   string
	Set     bool
	Compare compare
}

type compare struct {
	Op    string
	Value string
}

// TestOutput represents output from tests
type TestOutput struct {
	TestResult     bool
	ActualResult   string
	ExpectedResult string
}

func (t *testItem) execute(s string, isMultipleOutput bool) (result TestOutput, err error) {
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

// Execute perfoms benchmark tests
func (ts *Tests) Execute(s, testID string, isMultipleOutput bool) *TestOutput {
	finalOutput := &TestOutput{}
	var result bool
	var err error

	if ts == nil {
		return finalOutput
	}

	res := make([]TestOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	for i, t := range ts.TestItems {
		res[i], err = t.execute(s, isMultipleOutput)
		if err != nil {
			glog.V(2).Infof("Failed running test %s. %s", testID, err)
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
		`(?:^|[\s]+)"?` + flag + `"?\s*[=:][\r\t\f\v ]*"(.*)"`,
		`(?:^|[\s]+)"?` + flag + `"?\s*[=:][\r\t\f\v ]*([^\s]*)`,
		`(?:^|[\s]+)"?` + flag + `"?\s+([^-\s]+)`,
		`(?:^|[\s]+)` + `(` + flag + `)` + `(?:[\s]|$)`,
		flag + `[=:]([^\s]*)`,
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
	var match bool
	var flagVal string

	if t.Flag == "" {
		var jsonInterface interface{}

		if t.Path != "" {
			err := unmarshal(output, &jsonInterface)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load YAML or JSON from provided input \"%s\": %v\n", output, err)
				return false, "", errors.New("failed to load YAML or JSON")
			}
		}

		jsonpathResult, err := executeJSONPath(t.Path, &jsonInterface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to parse path expression \"%s\": %v\n", t.Path, err)
			return false, "", errors.New("error executing path expression")
		}
		match = (jsonpathResult != "")
		flagVal = jsonpathResult
	}
	if t.Set {
		if t.Compare.Op != "" {
			if !match {
				flagVal = getFlagValue(output, t.Flag)
			}

			TestResult, ExpectedResult, err = compareOp(t.Compare.Op, flagVal, t.Compare.Value, t.Flag)
		} else {
			ExpectedResult = fmt.Sprintf("'%s' Is present", t.Flag)
			TestResult, _ = regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, output)
		}
	} else {
		ExpectedResult = fmt.Sprintf("'%s' Is not present", t.Flag)
		r, _ := regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, output)
		TestResult = !r
	}
	glog.V(3).Infof("evaluate ExpectedResult: %s", ExpectedResult)
	glog.V(3).Infof("evaluate TestResult: %v", TestResult)
	if err != nil {
		glog.V(2).Infof("evaluate Error: %v", err)
	}
	return TestResult, ExpectedResult, err
}

func compareOp(tCompareOp, flagVal, tCompareValue, flagName string) (bool, string, error) {
	expectedResultPattern := ""
	testResult := false
	glog.V(3).Infof("Actual value flag '%s' = '%s'", flagName, flagVal)
	switch tCompareOp {
	case "eq":
		expectedResultPattern = "'%s' is equal to '%s'"
		value := strings.ToLower(flagVal)
		// In case the result should be empty, changing the status to indicate "No output"
		if tCompareValue == "" && flagVal == "" {
			expectedResultPattern = "%s '%s' has no output"
		}
		// Do case insensitive comparison for booleans ...
		if value == "false" || value == "true" {
			testResult = value == tCompareValue
		} else {
			testResult = flagVal == tCompareValue
		}

	case "noteq":
		expectedResultPattern = "'%s' is not equal to '%s'"
		value := strings.ToLower(flagVal)
		// Do case insensitive comparison for booleans ...
		if value == "false" || value == "true" {
			testResult = !(value == tCompareValue)
		} else {
			testResult = !(flagVal == tCompareValue)
		}

	case "gt", "gte", "lt", "lte":
		a, b, err := toNumeric(flagVal, tCompareValue)
		if err != nil {
			expectedResultPattern = "Invalid Number(s) used for comparison: '%s' '%s'"
			glog.V(1).Infof(fmt.Sprintf("Not numeric value - flag: %q - compareValue: %q %v\n", flagVal, tCompareValue, err))
			return false, fmt.Sprintf(expectedResultPattern, flagVal, tCompareValue), fmt.Errorf("not numeric value - flag: %q - compareValue: %q %v", flagVal, tCompareValue, err)
		}
		switch tCompareOp {
		case "gt":
			expectedResultPattern = "'%s' is greater than %s"
			testResult = a > b

		case "gte":
			expectedResultPattern = "'%s' is greater or equal to %s"
			testResult = a >= b

		case "lt":
			expectedResultPattern = "'%s' is lower than %s"
			testResult = a < b

		case "lte":
			expectedResultPattern = "'%s' is lower or equal to %s"
			testResult = a <= b
		}

	case "has":
		expectedResultPattern = "'%s' has '%s'"
		testResult = strings.Contains(flagVal, tCompareValue)

	case "nothave":
		expectedResultPattern = "'%s' does not have '%s'"
		testResult = !strings.Contains(flagVal, tCompareValue)

	case "regex":
		expectedResultPattern = "'%s' matched by regex expression '%s'"
		opRe := regexp.MustCompile(tCompareValue)
		testResult = opRe.MatchString(flagVal)

	case "valid_elements":
		expectedResultPattern = "'%s' contains valid elements from '%s'"
		s := splitAndRemoveLastSeparator(flagVal, defaultArraySeparator)
		target := splitAndRemoveLastSeparator(tCompareValue, defaultArraySeparator)
		testResult = allElementsValid(s, target)

	case "bitmask":
		expectedResultPattern = "'%s' has permissions " + flagVal + ", expected %s or more restrictive"
		requested, err := strconv.ParseInt(flagVal, 8, 64)
		if err != nil {
			expectedResultPattern = "'%s' has a non numeric value: '%s'"
			return false, fmt.Sprintf(expectedResultPattern, flagName, flagVal), fmt.Errorf("not numeric value - flag: %q - compareValue: %q %v", flagVal, tCompareValue, err)
		}
		max, err := strconv.ParseInt(tCompareValue, 8, 64)
		if err != nil {
			expectedResultPattern = "'%s' is testing for a non numeric value: '%s'"
			return false, fmt.Sprintf(expectedResultPattern, flagName, tCompareValue), fmt.Errorf("not numeric value - flag: %q - compareValue: %q %v", flagVal, tCompareValue, err)
		}
		testResult = (max & requested) == requested
	default:
		return testResult, expectedResultPattern, nil
	}

	return testResult, fmt.Sprintf(expectedResultPattern, flagName, tCompareValue), nil
}

func allElementsValid(s, t []string) bool {
	sourceEmpty := len(s) == 0
	targetEmpty := len(t) == 0

	if sourceEmpty && targetEmpty {
		return true
	}

	// XOR comparison -
	//     if either value is empty and the other is not empty,
	//     not all elements are valid
	if (sourceEmpty || targetEmpty) && !(sourceEmpty && targetEmpty) {
		return false
	}

	for _, sv := range s {
		found := false
		for _, tv := range t {
			if sv == tv {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func splitAndRemoveLastSeparator(s, sep string) []string {
	cleanS := strings.TrimRight(strings.TrimSpace(s), sep)
	if len(cleanS) == 0 {
		return []string{}
	}

	ts := strings.Split(cleanS, sep)
	for i := range ts {
		ts[i] = strings.TrimSpace(ts[i])
	}

	return ts
}

func unmarshal(s string, jsonInterface *interface{}) error {
	// We don't know whether it's YAML or JSON but
	// we can just try one then the other
	data := []byte(s)
	err := json.Unmarshal(data, jsonInterface)
	if err != nil {
		err := yaml.Unmarshal(data, jsonInterface)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeJSONPath(path string, jsonInterface interface{}) (string, error) {
	j := jsonpath.New("jsonpath")
	j.AllowMissingKeys(true)
	err := j.Parse(path)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	err = j.Execute(buf, jsonInterface)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (t *testItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type buildTest testItem

	// Make Set parameter to be treu by default.
	newTestItem := buildTest{Set: true}
	err := unmarshal(&newTestItem)
	if err != nil {
		return err
	}
	*t = testItem(newTestItem)
	return nil
}
