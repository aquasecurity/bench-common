package outputter

import (
	"io"

	"github.com/aquasecurity/bench-common/util"
)

func OutputToFile(data, filename string) error {
	util.PrintOutput(data, filename)
	return nil
}

func OutputToWriter(data string, w io.Writer) error {
	return nil
}
