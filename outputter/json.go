package outputter

import (
	"fmt"

	"github.com/aquasecurity/bench-common/check"
)

type JSONConverter interface {
	ConvertToJSON(controls *check.Controls) ([]byte, error)
}

type JSONDelegate struct{}

type JSON struct {
	FileHandler FileHandler
	Converter   JSONConverter
	Filename    string
	controls    *check.Controls
}

func NewJSON(outputFile string) *JSON {
	return &JSON{
		FileHandler: NewFile(outputFile),
		Converter:   &JSONDelegate{},
	}
}

var ErrFileHandlerRequired = fmt.Errorf("JSON - FileHandler is required")
var ErrConverterRequired = fmt.Errorf("JSON - Converter is required")
var ErrMissingControls = fmt.Errorf("JSON - Controls are required")

func (jrp *JSON) Output(controls *check.Controls, summary check.Summary) error {
	jrp.controls = controls
	if err := jrp.Validate(); err != nil {
		return err
	}

	out, err := jrp.Converter.ConvertToJSON(controls)
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	err = jrp.FileHandler.Handle(string(out))
	if err != nil {
		return fmt.Errorf("JSON - error Writing data: %v", err)
	}

	return nil
}

func (jrp *JSON) Validate() error {
	if jrp.controls == nil {
		return ErrMissingControls
	}

	if jrp.FileHandler == nil {
		return ErrFileHandlerRequired
	}

	if jrp.Converter == nil {
		return ErrConverterRequired
	}
	return nil
}

func (jd *JSONDelegate) ConvertToJSON(controls *check.Controls) ([]byte, error) {
	if controls == nil {
		return nil, ErrMissingControls
	}
	return controls.JSON()
}
