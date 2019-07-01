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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/golang/glog"
)

var (
	// Print colors
	Colors = map[State]*color.Color{
		PASS: color.New(color.FgGreen),
		FAIL: color.New(color.FgRed),
		WARN: color.New(color.FgYellow),
		INFO: color.New(color.FgBlue),
	}
)

func printlnWarn(msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		Colors[WARN].Sprintf("%s", WARN),
		msg,
	)
}

func sprintlnWarn(msg string) string {
	return fmt.Sprintf("[%s] %s",
		Colors[WARN].Sprintf("%s", WARN),
		msg,
	)
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

func CleanIDs(list string) []string {
	if list == "" {
		return nil
	}
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	for _, id := range ids {
		id = strings.Trim(id, " ")
	}

	return ids
}

// colorPrint outputs the state in a specific colour, along with a message string
func ColorPrint(state State, s string) {
	Colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
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

func PrintRawOutput(output string) {
	for _, row := range strings.Split(output, "\n") {
		fmt.Println(fmt.Sprintf("\t %s", row))
	}
}


func HandleError(err error, context string) (errmsg string) {
	if err != nil {
		errmsg = fmt.Sprintf("%s, error: %s\n", context, err)
	}
	return
}

// ExitWithError takes terminates execution with error message.
func ExitWithError(err error) {
	fmt.Fprintf(os.Stderr, "\n%v\n", err)
	os.Exit(1)
}

func writeOutputToFile(output string, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, output)
	return w.Flush()
}

func PrintOutput(output string, outputFile string) {
	if len(outputFile) == 0 {
		fmt.Println(output)
	} else {
		err := writeOutputToFile(output, outputFile)
		if err != nil {
			s := fmt.Sprintf("Failed to write to output file %s", outputFile)
			continueWithError(err, sprintlnWarn(s))
		}
	}
}
