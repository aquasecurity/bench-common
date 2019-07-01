package actioneval

import (
	"fmt"
	"github.com/aquasecurity/bench-common/util"
	"strings"

	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/bench-common/mockdata"
	"gopkg.in/yaml.v2"
)

var tmpFile = getTemporaryFileName()

func getTemporaryFileName() string{

	f,err:= ioutil.TempFile(os.TempDir(), "test_text_search_content")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	return f.Name()
}

func TestTextSearchFailState(t *testing.T) {
	testCases := []struct {
		yaml          string
		expectedState util.State
		testName      string
		workspace     string
		errmsg        string
	}{
		{mockdata.TestData1,
			util.FAIL,
			"Test for wrong root path", "",
			"no such file or directory"},

		{fmt.Sprintf(mockdata.TestData2, getTemporaryFileName(), "build", "exact"),
			util.FAIL,
			"Test relative workspace path", "/root/../../../a.txt",
			"are not supported"},

		{fmt.Sprintf(mockdata.TestData2, getTemporaryFileName(), 555, "wrong_type"),
			util.FAIL,
			"Test for wrong type", "/",
			"no results found"},

		{fmt.Sprintf(mockdata.TestData2, "/tmp", "", ""),
			util.FAIL,
			"Test for file type", "/",
			"invalid file"},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s", tc.testName), func(t *testing.T) {
			var args yaml.MapSlice
			if err := yaml.Unmarshal([]byte(tc.yaml), &args); err != nil {
				t.Errorf("test fail: yaml unmarshal failed %v\n", err.Error())
				return
			}

			mockdata.CreateContentFile(tmpFile)
			defer os.Remove(tmpFile)

			testSearch := NewTextSearchFilter(args)
			var res = testSearch.SearchFilterHandler(tc.workspace, false)

			if res.State != tc.expectedState {
				t.Errorf("test fail: expected: %v actual: %v\n", tc.expectedState, res.State)
				return
			}

			if !strings.Contains(res.Errmsgs, tc.errmsg) {
				t.Errorf("test fail: expected err: %v actual: %v\n", tc.errmsg, res.Errmsgs)
				return

			}
		})
	}
}

// 4 tests in one testsuite
func TestTextSearchLinesCount(t *testing.T) {
	testCases := []struct {
		yaml               string
		testName           string
		workspace          string
		expectedLinesCount int
	}{
		{fmt.Sprintf(mockdata.TestData2, tmpFile, "able", "contains"),
			"Text Search 'Contains'",
			"/",
			3,
		},
		{fmt.Sprintf(mockdata.TestData2, tmpFile, "build", "contains"),
			"Text Search 'Contains'",
			"/",
			10,
		},
		{fmt.Sprintf(mockdata.TestData2, tmpFile, "able", "hasPrefix"),
			"Text Search 'hasPrefix'",
			"/",
			2,
		},
		{fmt.Sprintf(mockdata.TestData2, tmpFile, "ing", "hasSuffix"),
			"Text Search 'hasSuffix'",
			"/",
			14,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s", tc.testName), func(t *testing.T) {
			var args yaml.MapSlice
			if err := yaml.Unmarshal([]byte(tc.yaml), &args); err != nil {
				t.Errorf("test fail: yaml unmarshal failed %v\n", err.Error())
				return
			}

			mockdata.CreateContentFile(tmpFile)
			defer os.Remove(tmpFile)

			testSearch := NewTextSearchFilter(args)
			var res = testSearch.SearchFilterHandler(tc.workspace, false)

			if res.Lines != tc.expectedLinesCount {
				t.Errorf("test fail: expected: %v actual: %v, err: %v", tc.expectedLinesCount, res.Lines, res.Errmsgs)
			}
		})
	}
}

func setupDummyImageFs() (string, error) {

	innerTmpDir, err := ioutil.TempDir("", "myDir")
	if err != nil {
		return "", err
	}

	os.MkdirAll(path.Join(innerTmpDir, "imageroot/etc"), 0777)
	os.MkdirAll(path.Join(innerTmpDir, "outside/etc"), 0777)

	ioutil.WriteFile(path.Join(innerTmpDir, "outside/etc/passwd"), []byte("dfdfd"), 0644)
	os.Symlink(path.Join(innerTmpDir, "outside/etc/passwd"), path.Join(innerTmpDir, "imageroot/etc/passwd.lnk"))

	return innerTmpDir, nil
}

func TestTextSearchLink(t *testing.T) {

	tmpDir, _ := setupDummyImageFs()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestData2, "/etc/passwd.lnk", 555, 666)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler(path.Join(tmpDir, "/imageroot"), false)
	if res.State != util.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", util.FAIL, res.State, res.Errmsgs)
	}
}
