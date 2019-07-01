package actioneval

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/aquasecurity/bench-common/mockdata"
	"github.com/aquasecurity/bench-common/util"
	"gopkg.in/yaml.v2"
)

func setUp() (string, error) {

	innerTmpDir, err := ioutil.TempDir("", "myDir")
	if err != nil {
		return "", err
	}

	/// create mock files array

	// go over mock files array and create it on physical device
	for _, item := range mockdata.Mockfiles {
		if item.Ftype == 0 {
			ioutil.WriteFile(path.Join(innerTmpDir, item.File), []byte("test"), item.Perm)
			os.Chmod(path.Join(innerTmpDir, item.File), item.Perm)
		} else if item.Ftype == os.ModeDir {
			os.Mkdir(path.Join(innerTmpDir, item.File), item.Perm)
		} else if item.Ftype == os.ModeSymlink {
			os.Symlink(path.Join(innerTmpDir, "test1"), path.Join(innerTmpDir, item.File))
		}
	}
	return innerTmpDir, nil
}

func TestFileSearchRelativeDir(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilter, tmpDir, "/", "test", "contains")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/root/..//.../aaa", false)
	if res.State != util.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", util.FAIL, res.State, res.Errmsgs)
	}
}


func TestWithTarHeaders(t *testing.T) {

	var headers []tar.Header

	if err := json.Unmarshal(mockdata.TarHeadersForTests, &headers); err != nil {
		t.Errorf("test fail: yaml unmarshal tar json %v", err.Error())
		return
	}
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchPermission, "/etc", 0755)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	fileSearchFilter = fileSearchFilter.WithTarHeaders(headers)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 10 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 6, res.Lines, res.Errmsgs)
	}
}

func TestWithTarHeadersSetUid(t *testing.T) {

	var headers []tar.Header

	if err := json.Unmarshal(mockdata.TarHeadersForTests, &headers); err != nil {
		t.Errorf("test fail: yaml unmarshal tar json %v", err.Error())
		return
	}
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchAllBitsPermission, "/etc", 04000)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	fileSearchFilter = fileSearchFilter.WithTarHeaders(headers)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 1 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 6, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchFilter_SearchFilterHandler(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	type fields struct {
		searchLocation string
		filter         string
		filterType     util.TextFilterType
		fileType       util.FileFilterType
		perm           int64
		sMode          util.PermissionSearchMode
		tarHeaders     []tar.Header
		groupId        int64
		userId         int64
	}
	type args struct {
		workspacePath string
		count         bool
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		expectedFoundLines int
	}{
		{"Test Search all files",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterAll,
				-1,
				util.ModeAnyBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			24},

		{"Test Search world files",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterAll,
				0777,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			7,
		},

		{"Test Search symbolic links",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterSymblink,
				-1,
				util.ModeAnyBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			6,
		},
		{"Test Search regular files",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterRegularFile,
				-1,
				util.ModeAnyBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			11,
		},
		{"Test Search directories",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterDirectory,
				-1,
				util.ModeAnyBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			7,
		},
		{"Test Search with permission 0700 files",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterRegularFile,
				0700,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			1,
		},
		{"Test Search with permission 0700 directories",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterDirectory,
				0700,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			2,
		},
		{"Test Search file test6 with permission 0200",
			fields{
				"/",
				"test6",
				util.TextFilterExact,
				util.FileFilterRegularFile,
				0200,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			1,
		},
		{"Test Search file that starts with 'Image' and permission 0200",
			fields{
				"/",
				"Image",
				util.TextFilterHasPrefix,
				util.FileFilterRegularFile,
				0200,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			4,
		},
		{"Test Search file that ends with '.jpg' and permission 0200",
			fields{
				"/",
				".jpg",
				util.TextFilterHasSuffix,
				util.FileFilterRegularFile,
				0200,
				util.ModeExact,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			4,
		},
		{"Test Search file that contains 'test'",
			fields{
				"/",
				"test",
				util.TextFilterContains,
				util.FileFilterAll,
				0,
				util.ModeAnyBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			23,
		},
		{"Test Find setuid",
			fields{
				"/",
				"",
				util.TextFilterContains,
				util.FileFilterAll,
				040000000,
				util.ModeAllBits,
				nil,
				-1,
				-1},
			args{workspacePath: tmpDir, count: false},
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FileSearchFilter{
				searchLocation: tt.fields.searchLocation,
				filter:         tt.fields.filter,
				filterType:     tt.fields.filterType,
				fileType:       tt.fields.fileType,
				perm:           tt.fields.perm,
				sMode:          tt.fields.sMode,
				tarHeaders:     tt.fields.tarHeaders,
				groupId:        tt.fields.groupId,
				userId:         tt.fields.userId,
			}
			if gotResult := f.SearchFilterHandler(tt.args.workspacePath, tt.args.count); gotResult.Lines != tt.expectedFoundLines {
				t.Errorf("FileSearchFilter.SearchFilterHandler() = %v, want %v", gotResult.Lines, tt.expectedFoundLines)
			}
		})
	}
}

func Test_convertMode(t *testing.T) {
	type args struct {
		mode int64
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{"test mode",
			args{0777},
			0777,
		},
		{"test setuid",
			args{04000},
			040000000,
		},
		{"test setuid",
			args{02000},
			020000000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertMode(tt.args.mode); got != tt.want {
				t.Errorf("convertMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parsePermission(t *testing.T) {
	type args struct {
		perm string
	}
	tests := []struct {
		name        string
		args        args
		wantPermInt int64
		wantMode    util.PermissionSearchMode
		wantErr     bool
	}{
		{
			"Test -200",
			args{"-200"},
			0200,
			util.ModeAllBits,
			false,
			},
		{
			"Test 777",
			args{"777"},
			0777,
			util.ModeExact,
			false,
		},
		{
			"Test 4000",
			args{"4000"},
			040000000,
			util.ModeExact,
			false,
		},
		{
			"Test /600",
			args{"/600"},
			0600,
			util.ModeAnyBits,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPermInt, gotMode, err := parsePermission(tt.args.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePermission() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPermInt != tt.wantPermInt {
				t.Errorf("parsePermission() gotPermInt = %v, want %v", gotPermInt, tt.wantPermInt)
			}
			if !reflect.DeepEqual(gotMode, tt.wantMode) {
				t.Errorf("parsePermission() gotMode = %v, want %v", gotMode, tt.wantMode)
			}
		})
	}
}
