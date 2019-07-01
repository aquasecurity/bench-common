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

package cmd

import (
	"fmt"
	"github.com/aquasecurity/bench-common/runner"
	"github.com/aquasecurity/bench-common/util"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

func app(cmd *cobra.Command, args []string) {
	err := checkDefinitionFilePath(cfgFile)
	if err != nil {
		//common.ExitWithError(err)

	}

	Main(cfgFile, define)
}

func Main(filePath string, constraints []string) {

	if data, err := ioutil.ReadFile(filePath); err == nil {
		if runner, err := runner.New(data).
			WithCheckList("").
			WithConstrains(constraints).
			Build(); err == nil {
			if err := runner.RunTestsWithOutput(jsonFmt,outputFile, noRemediations, includeTestOutput); err != nil {
				util.ExitWithError(err)
			}

		} else {
			util.ExitWithError(err)
		}

	} else {
		util.ExitWithError(err)
	}

}

func checkDefinitionFilePath(filePath string) (err error) {
	glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", filePath))
	_, err = os.Stat(filePath)

	return err
}
