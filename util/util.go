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
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/aquasecurity/bench-common/check"
	"github.com/fatih/color"
	"github.com/golang/glog"
)

var (
	// Print colors
	colors = map[check.State]*color.Color{
		check.PASS: color.New(color.FgGreen),
		check.FAIL: color.New(color.FgRed),
		check.WARN: color.New(color.FgYellow),
		check.INFO: color.New(color.FgBlue),
	}
)

func printlnWarn(msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		colors[check.WARN].Sprintf("%s", check.WARN),
		msg,
	)
}

func sprintlnWarn(msg string) string {
	return fmt.Sprintf("[%s] %s",
		colors[check.WARN].Sprintf("%s", check.WARN),
		msg,
	)
}

// ExitWithError takes terminates execution with error message.
func ExitWithError(err error) {
	fmt.Fprintf(os.Stderr, "\n%v\n", err)
	os.Exit(1)
}

func continueWithError(err error, msg string) string {
	if err != nil {
		glog.V(1).Info(err)
	}

	if msg != "" {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}

	return ""
}

func cleanIDs(list string) []string {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	for _, id := range ids {
		id = strings.Trim(id, " ")
	}

	return ids
}

// colorPrint outputs the state in a specific colour, along with a message string
func colorPrint(state check.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// prettyPrint outputs the results to stdout in human-readable format
func PrettyPrint(r *check.Controls, summary check.Summary) {
	colorPrint(check.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Description))
	for _, g := range r.Groups {
		colorPrint(check.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Description))
		for _, c := range g.Checks {
			colorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Description))
		}
	}

	fmt.Println()

	// Print remediations.
	if summary.Fail > 0 || summary.Warn > 0 {
		colors[check.WARN].Printf("== Remediations ==\n")
		for _, g := range r.Groups {
			for _, c := range g.Checks {
				if c.State != check.PASS {
					fmt.Printf("%s %s\n", c.ID, c.Remediation)
				}
			}
		}
		fmt.Println()
	}

	// Print summary setting output color to highest severity.
	var res check.State
	if summary.Fail > 0 {
		res = check.FAIL
	} else if summary.Warn > 0 {
		res = check.WARN
	} else {
		res = check.PASS
	}

	colors[res].Printf("== Summary ==\n")
	fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n",
		summary.Pass, summary.Fail, summary.Warn,
	)
}

// verifyBin checks that the binary specified is running
func verifyBin(bin string, psFunc func(string) string) bool {

	// Strip any quotes
	bin = strings.Trim(bin, "'\"")

	// bin could consist of more than one word
	// We'll search for running processes with the first word, and then check the whole
	// proc as supplied is included in the results
	proc := strings.Fields(bin)[0]
	out := psFunc(proc)

	return strings.Contains(out, bin)
}

func verifyKubeVersion(major string, minor string) {
	// These executables might not be on the user's path.

	_, err := exec.LookPath("kubectl")
	if err != nil {
		continueWithError(err, sprintlnWarn("Kubernetes version check skipped"))
		return
	}

	cmd := exec.Command("kubectl", "version")
	out, err := cmd.Output()
	if err != nil {
		s := fmt.Sprintf("Kubernetes version check skipped with error %v", err)
		continueWithError(err, sprintlnWarn(s))
		if len(out) == 0 {
			return
		}
	}

	msg := checkVersion("Client", string(out), major, minor)
	if msg != "" {
		continueWithError(fmt.Errorf(msg), msg)
	}

	msg = checkVersion("Server", string(out), major, minor)
	if msg != "" {
		continueWithError(fmt.Errorf(msg), msg)
	}
}

var regexVersionMajor = regexp.MustCompile("Major:\"([0-9]+)\"")
var regexVersionMinor = regexp.MustCompile("Minor:\"([0-9]+)\"")

func checkVersion(x string, s string, expMajor string, expMinor string) string {
	regexVersion, err := regexp.Compile(x + " Version: version.Info{(.*)}")
	if err != nil {
		return fmt.Sprintf("Error checking Kubernetes version: %v", err)
	}

	ss := regexVersion.FindString(s)
	major := versionMatch(regexVersionMajor, ss)
	minor := versionMatch(regexVersionMinor, ss)
	if major == "" || minor == "" {
		return fmt.Sprintf("Couldn't find %s version from kubectl output '%s'", x, s)
	}

	if major != expMajor || minor != expMinor {
		return fmt.Sprintf("Unexpected %s version %s.%s", x, major, minor)
	}

	return ""
}

func versionMatch(r *regexp.Regexp, s string) string {
	match := r.FindStringSubmatch(s)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}
