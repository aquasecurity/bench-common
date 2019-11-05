package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

var errMissingFilename = fmt.Errorf("filename is required")
var errMissingIOWriter = fmt.Errorf("IOWriter is required")

type FileHandler interface {
	Handle(data string) error
}

type File struct {
	Filename string
	IOWriter IOWriter
}

type FileDelegate struct{}

type IOWriter interface {
	OutputToWriter(data string, w io.Writer) error
}

type IOWriteDelegate struct{}

func NewFile(filename string) *File {
	return &File{
		Filename: filename,
		IOWriter: &IOWriteDelegate{},
	}
}

func (f *File) Handle(data string) error {
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

	return f.IOWriter.OutputToWriter(data, w)
}

func (f *File) validate() error {
	if f.Filename == "" {
		return errMissingFilename
	}

	if f.IOWriter == nil {
		return errMissingIOWriter
	}

	return nil
}

func (iowd *IOWriteDelegate) OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, data)
	return err
}
