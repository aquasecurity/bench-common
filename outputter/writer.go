package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

var errMissingIOWriter = fmt.Errorf("IOWriter is required")

type fileHandler interface {
	Handle(data string) error
}

type file struct {
	Filename string
	ioWriter ioWriter
}

type ioWriter interface {
	OutputToWriter(data string, w io.Writer) error
}

type ioWriteDelegate struct{}

func newFile(filename string) *file {
	return &file{
		Filename: filename,
		ioWriter: &ioWriteDelegate{},
	}
}

func (f *file) Handle(data string) error {
	if err := f.validate(); err != nil {
		return err
	}

	var w io.Writer
	if len(f.Filename) == 0 {
		w = os.Stdout
	} else {
		file, err := os.Create(f.Filename)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}

	writer := bufio.NewWriter(w)
	defer writer.Flush()

	return f.ioWriter.OutputToWriter(data, w)
}

func (f *file) validate() error {
	if f.ioWriter == nil {
		return errMissingIOWriter
	}

	return nil
}

func (iowd *ioWriteDelegate) OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, data)
	return err
}
