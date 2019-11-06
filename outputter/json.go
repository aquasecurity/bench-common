package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

// JSON outputter functionality for JSON payload
type JSON struct {
	fileHandler fileHandler
	Filename    string
	controls    *check.Controls
}

// NewJSON creates new Outputter of type JSON
func NewJSON(outputFile string) *JSON {
	return &JSON{
		fileHandler: newFile(outputFile),
	}
}

var errFileHandlerRequired = fmt.Errorf("fileHandler is required")
var errMissingControls = fmt.Errorf("controls are required")

// Output displays Control results as JSON payload
func (jrp *JSON) Output(controls *check.Controls, summary check.Summary) error {
	jrp.controls = controls
	if err := jrp.validate(); err != nil {
		return err
	}

	out, err := controls.JSON()
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	err = jrp.fileHandler.Handle(string(out))
	if err != nil {
		return fmt.Errorf("JSON - error Writing data: %v", err)
	}

	return nil
}

func (jrp *JSON) validate() error {
	if jrp.controls == nil {
		return errMissingControls
	}

	if jrp.fileHandler == nil {
		return errFileHandlerRequired
	}

	return nil
}
