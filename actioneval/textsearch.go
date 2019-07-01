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
	"bufio"
	"fmt"
	"github.com/aquasecurity/bench-common/util"
	"gopkg.in/yaml.v2"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
)

type TextSearchFilter struct {
	searchLocation string
	filter         string
	filterType     util.YamlEntityValue
}

func NewTextSearchFilter(mapSlice yaml.MapSlice) SearchFilter {

	filter := new(TextSearchFilter)

	for _, mapItem := range mapSlice {

		key := fmt.Sprintf("%v", mapItem.Key)
		val := fmt.Sprintf("%v", mapItem.Value)

		switch util.YamlEntityName(key) {
		case util.PathEntity:
			filter.searchLocation = val
		case util.FilterEntity:
			filter.filter = val
		case util.FilterTypeEntity:
			filter.filterType = util.YamlEntityValue(val)
		}
	}

	return filter
}

func (t *TextSearchFilter) SearchFilterHandler(workspacePath string, count bool) (result SearchFilterResult) {

	rootPath := path.Join(workspacePath, t.searchLocation)
	clearRootPath := path.Clean(rootPath)
	// ensure that search location does not escape the workspace
	if !strings.HasPrefix(clearRootPath, workspacePath) {
		result.Errmsgs += util.HandleError(fmt.Errorf("relative path "+rootPath+" are not supported "), reflect.TypeOf(t).String())
		result.State = util.FAIL
		return result
	}

	if fileStat, statErr := os.Lstat(clearRootPath); statErr != nil {
		result.Errmsgs += util.HandleError(statErr, reflect.TypeOf(t).String())
		result.State = util.FAIL
		return result
	} else {
		if fileStat.Mode()&os.ModeSymlink != 0 { // is link
			// ensure that link does not refer outside of the image path
			var realPath, err = filepath.EvalSymlinks(clearRootPath)
			if err != nil {
				result.Errmsgs += util.HandleError(err, reflect.TypeOf(t).String())
				result.State = util.FAIL
				return result
			}

			if !strings.HasPrefix(realPath, workspacePath) {
				result.Errmsgs += util.HandleError(fmt.Errorf("Symbolic link file "+clearRootPath+" refers to "+realPath+" , that is out of image fs scope"), reflect.TypeOf(t).String())
				result.State = util.FAIL
				return result
			}
			// ensure this is regular file i.e. not dir or socket file ...
		} else if !fileStat.Mode().IsRegular() {
			result.Errmsgs += util.HandleError(fmt.Errorf("invalid file "+clearRootPath), reflect.TypeOf(t).String())
			result.State = util.FAIL
			return result

		}
	}

	//first step try to open the file
	f, err := os.Open(clearRootPath)
	defer f.Close()

	if err != nil {
		result.Errmsgs += util.HandleError(fmt.Errorf("Unable to open file"+f.Name()), reflect.TypeOf(t).String())
		result.State = util.FAIL
		return result
	}

	var match bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		match = false
		for _, word := range strings.Fields(line) {
			if t.filterType == util.HasPrefixVal && strings.HasPrefix(word, t.filter) ||
				t.filterType == util.HasSuffixVal && strings.HasSuffix(word, t.filter) ||
				t.filterType == util.ContainsVal && strings.Contains(word, t.filter) {
				match = true
				break
			}
		}
		if match {
			result.Lines++
			if !count { //append lines when count false , otherwise reserve "out" for counter
				result.Output.WriteString(line + "\n")
			}
		}
	}
	if result.Lines == 0 {
		result.Errmsgs += util.HandleError(fmt.Errorf("no results found"), reflect.TypeOf(t).String())
		result.State = util.FAIL
	}
	if count {
		result.Output.Reset()
		result.Output.WriteString(fmt.Sprintf("%d\n", result.Lines))
	}
	return result
}
