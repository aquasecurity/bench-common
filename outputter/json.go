package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type JSON struct {
	FileHandler FileHandler
	Filename    string
	controls    *check.Controls
}

func NewJSON(outputFile string) *JSON {
	return &JSON{
		FileHandler: NewFile(outputFile),
	}
}

var errFileHandlerRequired = fmt.Errorf("fileHandler is required")
var errMissingControls = fmt.Errorf("controls are required")

func (jrp *JSON) Output(controls *check.Controls, summary check.Summary) error {
	jrp.controls = controls
	if err := jrp.validate(); err != nil {
		return err
	}

	out, err := controls.JSON()
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	err = jrp.FileHandler.Handle(string(out))
	if err != nil {
		return fmt.Errorf("JSON - error Writing data: %v", err)
	}

	return nil
}

func (jrp *JSON) validate() error {
	if jrp.controls == nil {
		return errMissingControls
	}

	if jrp.FileHandler == nil {
		return errFileHandlerRequired
	}

	return nil
}
