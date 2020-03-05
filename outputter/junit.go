package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

// JUnit outputter functionality for JUnit output
type JUnit struct {
	fileHandler fileHandler
	Filename    string
	controls    *check.Controls
}

// NewJUnit creates new Outputter of type JUnit
func NewJUnit(outputFile string) *JUnit {
	return &JUnit{
		fileHandler: newFile(outputFile),
	}
}

// Output displays Control results as JUnit payload
func (jrp *JUnit) Output(controls *check.Controls, summary check.Summary) error {
	jrp.controls = controls
	if err := jrp.validate(); err != nil {
		return err
	}

	out, err := controls.JUnit()
	if err != nil {
		return fmt.Errorf("JUnit - %v", err)
	}

	err = jrp.fileHandler.Handle(string(out))
	if err != nil {
		return fmt.Errorf("JUnit - error Writing data: %v", err)
	}

	return nil
}

func (jrp *JUnit) validate() error {
	if jrp.controls == nil {
		return errMissingControls
	}

	if jrp.fileHandler == nil {
		return errFileHandlerRequired
	}

	return nil
}
