package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

var errMissingFilename = fmt.Errorf("filename is required")
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
	file, err := os.Create(f.Filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	return f.ioWriter.OutputToWriter(data, w)
}

func (f *file) validate() error {
	if f.Filename == "" {
		return errMissingFilename
	}

	if f.ioWriter == nil {
		return errMissingIOWriter
	}

	return nil
}

func (iowd *ioWriteDelegate) OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, data)
	return err
}
