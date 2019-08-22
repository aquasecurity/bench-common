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
	FileWriter *FileWriter
	Converter  *JSONConverter
}

func NewJSON(outputFile string) *JSON {
	return &JSON{
		FileWriter: NewFile(outputfile),
		Converter:  &JSONDelegate{},
	}
}

func (jrp *JSON) Output(controls *check.Controls, summary check.Summary) error {
	if jrp.FileWriter == nil {
		return fmt.Errorf("JSON - FileWriter is required")
	}

	if jrp.Converter == nil {
		return fmt.Errorf("JSON - Converter is required")
	}

	out, err := jrp.Converter.ConvertToJSON(controls)
	if err != nil {
		return fmt.Errorf("JSON - %v", err)
	}

	err = jrp.FileWriter.Write(string(out))
	if err != nil {
		return fmt.Errorf("JSON - error Writing data: %v", err)
	}

	return nil
}

func (jd *JSONDelegate) ConvertToJSON(controls *check.Controls) ([]byte, error) {
	return controls.JSON()
}
