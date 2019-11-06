package outputter

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandle(t *testing.T) {
	dir, err := ioutil.TempDir("", "outputter_test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up

	testData := `{"id":"12121","text":"testControl","tests":null,"total_pass":0,"total_fail":0,"total_warn":0,"total_info":0,"DefinedConstraints":null}`
	testFilename := filepath.Join(dir, "test.json")

	//  ErrMissingFilename
	f := &file{}
	err = f.Handle(testData)
	if err == nil {
		t.Errorf("Unable to handle: %v", err)
	}

	//  ErrMissingFileManager
	f = &file{
		Filename: testFilename,
	}
	err = f.Handle(testData)
	if err == nil {
		t.Errorf("Unable to handle: %v", err)
	}

	//  ErrMissingIOWriter
	f = &file{
		Filename: testFilename,
	}
	err = f.Handle(testData)
	if err == nil {
		t.Errorf("Unable to handle: %v", err)
	}

	// Check file output
	f = &file{
		Filename: testFilename,
		ioWriter: &ioWriteDelegate{},
	}
	err = f.Handle(testData)
	if err != nil {
		t.Errorf("Unable to handle: %v", err)
	}

	if _, err := os.Stat(testFilename); os.IsNotExist(err) {
		t.Errorf("File was not created")
	}

	out, err := ioutil.ReadFile(testFilename)
	if err != nil {
		t.Errorf("Unexpected error reading test file: %v", err)
	}
	outTestFileData := strings.TrimSpace(string(out))

	if testData != outTestFileData {
		t.Errorf("Output Test Data does not match: [%s]  - [%s]", testData, outTestFileData)
	}

}
