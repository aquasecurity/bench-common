// Copyright © 2019 Aqua Security Software Ltd. <info@aquasec.com>
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

package actioneval

import (
	"archive/tar"
	"fmt"
	"github.com/aquasecurity/bench-common/util"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"gopkg.in/yaml.v2"
)

type FileSearchFilter struct {

	// location where to start the search
	searchLocation string
	// file name filter
	filter string
	// file name filter pattern values contains
	filterType util.TextFilterType

	//file type filter dir or symbolic link
	fileType util.FileFilterType
	// permission 0600,0777,/777 ,-666 etc...
	perm  int64
	sMode util.PermissionSearchMode

	tarHeaders []tar.Header

	groupId int64
	userId  int64
}

func (f *FileSearchFilter) WithTarHeaders(tarHeaders []tar.Header) *FileSearchFilter {
	f.tarHeaders = tarHeaders
	return f
}

func NewFileSearchFilter(mapSlice yaml.MapSlice) (filter *FileSearchFilter, err error) {

	filter = new(FileSearchFilter)
	// set default fileTypeFilter
	filter.fileType = util.FileFilterAll
	filter.userId = -1
	filter.groupId = -1
	for _, mapItem := range mapSlice {
		key, val := parseMapKeyValToString(mapItem)

		// parse 'args' section in yaml
		switch util.YamlEntityName(key) {
		case util.PathEntity:
			filter.searchLocation = val
		case util.FilterEntity:
			filter.filter = val
		case util.PermissionEntity:
			filter.perm, filter.sMode, err = parsePermission(val)
		case util.FileTypeEntity:
			filter.fileType = convertFileType(val)
		case util.FilterTypeEntity:
			filter.filterType = convertFilterType(val)
		case util.FilterGroupId:
			filter.groupId, err = strconv.ParseInt(val, 10, 64)
		case util.FilterUserId:
			filter.userId, err = strconv.ParseInt(val, 10, 64)
		}

		if err != nil {
			return nil, err
		}
	}
	return filter, err
}

func parseMapKeyValToString(item yaml.MapItem) (key string, val string) {
	key = fmt.Sprintf("%v", item.Key)
	val = fmt.Sprintf("%v", item.Value)
	return key, val
}

func convertFileType(fileType string) util.FileFilterType {
	switch util.YamlEntityValue(fileType) {
	case util.DirectoryVal:
		return util.FileFilterDirectory
	case util.SymblinkVal:
		return util.FileFilterSymblink
	case util.FileVal:
		return util.FileFilterRegularFile
	default:
		return util.FileFilterAll
	}

}

func convertFilterType(filterType string) util.TextFilterType {
	switch util.YamlEntityValue(filterType) {
	case util.ExactVal:
		return util.TextFilterExact
	case util.HasPrefixVal:
		return util.TextFilterHasPrefix
	case util.HasSuffixVal:
		return util.TextFilterHasSuffix
	case util.ContainsVal:
		fallthrough
	default:
		return util.TextFilterContains
	}
}

func (f *FileSearchFilter) SearchFilterHandler(workspacePath string, count bool) (result SearchFilterResult) {

	rootPath := path.Join(workspacePath, f.searchLocation)
	clearRootPath := path.Clean(rootPath)

	// ensure that search location does not escape the workspace
	if !strings.HasPrefix(clearRootPath, workspacePath) {
		result.Errmsgs += util.HandleError(fmt.Errorf("relative path "+rootPath+" is not supported "), reflect.TypeOf(f).String())
		result.State = util.FAIL
		return result
	}

	walkMethod := func(filePath string, info os.FileInfo, err error) error {

		loc := path.Join("/", filePath)
		if !strings.HasPrefix(loc, path.Clean(f.searchLocation)) {
			return nil
		}

		if !f.satisfyAllFilters(info) {
			return nil
		}

		result.Lines++
		result.Output.WriteString(loc + "\n")
		return nil
	}

	var walkErr error
	if f.tarHeaders == nil || len(f.tarHeaders) == 0{
		walkErr = filepath.Walk(clearRootPath, walkMethod)
	} else {
		for _, header := range f.tarHeaders {
			walkErr = walkMethod(header.Name, header.FileInfo(), nil)
		}
	}

	if walkErr != nil {
		result.Errmsgs += util.HandleError(fmt.Errorf(walkErr.Error()), reflect.TypeOf(f).String())
		result.State = util.FAIL
		return result
	}
	if count {
		result.Output.Reset()
		result.Output.WriteString(fmt.Sprintf("%d\n", result.Lines))
	}
	return result
}

func (f *FileSearchFilter) satisfyGroupIdAnUserIdFilter(info os.FileInfo) bool {

	uid, gid := GetFileOwner(info)
	//check groups

	if f.userId != -1 && uint32(f.userId) != uid {
		return false
	}

	if f.groupId != -1 && uint32(f.groupId) != gid {
		return false
	}

	return true
}
func (f *FileSearchFilter) satisfyAllFilters(info os.FileInfo) bool {

	if f.filter != "" &&
		!f.satisfyFilter(info.Name()) {
		return false
	}

	// check if we satisfy the permission filter condition
	if f.perm != 0 && f.sMode != 0 && !f.satisfyPermissionFilter(info) {
		return false
	}

	// check if we satisfy the file type filter condition
	if !f.satisfyFileType(info) {
		return false
	}

	if !f.satisfyGroupIdAnUserIdFilter(info) {
		return false
	}

	return true
}

func (f *FileSearchFilter) satisfyPermissionFilter(info os.FileInfo) bool {

	filePerm := int64(info.Mode())
	if (f.sMode == util.ModeExact && (filePerm&070000777 == f.perm)) ||
		(f.sMode == util.ModeAnyBits && (filePerm&f.perm != 0)) ||
		(f.sMode == util.ModeAllBits && (filePerm&f.perm == f.perm)) {
		return true
	}
	return false
}

func (f *FileSearchFilter) satisfyFilter(filename string) bool {

	if (f.filterType == util.TextFilterExact && strings.EqualFold(filename, f.filter)) ||
		(f.filterType == util.TextFilterHasPrefix && strings.HasPrefix(filename, f.filter)) ||
		(f.filterType == util.TextFilterHasSuffix && strings.HasSuffix(filename, f.filter)) ||
		(f.filterType == util.TextFilterContains && strings.Contains(filename, f.filter)) {
		return true
	}
	return false
}

//Verify the file type meets the criteria from yaml , i.e dir/symblink oor regular file
func (f *FileSearchFilter) satisfyFileType(fileInfo os.FileInfo) bool {

	fileInfo.Mode()
	if (f.fileType == util.FileFilterDirectory && fileInfo.IsDir()) ||
		(f.fileType == util.FileFilterSymblink && fileInfo.Mode()&os.ModeSymlink != 0) ||
		(f.fileType == util.FileFilterRegularFile && fileInfo.Mode().IsRegular()) ||
		(f.fileType == util.FileFilterAll) {
		return true
	}
	return false
}

//The permission search mode concept has been taken from unix command "find -perm ",
//which supports 3 modes, recognized by prefix '- or /'
//where '-' prefix means all permission bits are set and  the '/' prefix  means any permissions bits are set.
func parsePermission(perm string) (permInt int64, mode util.PermissionSearchMode, err error) {

	if strings.HasPrefix(perm, "-") { // all permission bits are set for the file
		mode = util.ModeAllBits
	} else if strings.HasPrefix(perm, "/") { // any permissions are set for the file
		mode = util.ModeAnyBits

	} else {
		mode = util.ModeExact
	}
	//strip non numeric chars
	reg, err := regexp.Compile("\\D")
	if err != nil {
		return 0, 0, err
	}

	perm = reg.ReplaceAllString(perm, "")
	if len(perm) == 4 || len(perm) == 3 {
		if permInt, err := strconv.ParseInt(reg.ReplaceAllString(perm, ""), 8, 64); err != nil {
			return 0, 0, err
		} else {
			return int64(convertMode(permInt)), mode, nil
		}
	} else {
		return permInt, mode, fmt.Errorf("invalid permission format %s", perm)
	}
}

// the input mode consist of 12 bits
// first three bits represents the sticky bit/setuid/setgid
// other 9 bits represents the file mode i.e 777
// in order to compare it with os.FileMode, need to convert to 32 bits
func convertMode(mode int64) uint64 {
	return (07000 & uint64(mode) << 12) | uint64(mode) & 0777
}
