package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

var ErrMissingFilename = fmt.Errorf("File - Filename is required")
var ErrMissingFileManager = fmt.Errorf("File - FileManager is required")
var ErrMissingIOWriter = fmt.Errorf("File - IOWriter is required")

type FileHandler interface {
	Handle(data string) error
}

type File struct {
	Filename    string
	FileManager FileManager
	IOWriter    IOWriter
}

type FileManager interface {
	ManageFile(filename string) (*os.File, error)
}

type FileDelegate struct{}

type IOWriter interface {
	OutputToWriter(data string, w io.Writer) error
}

type IOWriteDelegate struct{}

func NewFile(filename string) *File {
	return &File{
		Filename:    filename,
		FileManager: &FileDelegate{},
		IOWriter:    &IOWriteDelegate{},
	}
}

func (f *File) Handle(data string) error {
	if err := f.Validate(); err != nil {
		return err
	}
	file, err := f.FileManager.ManageFile(f.Filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	return f.IOWriter.OutputToWriter(data, w)
}

func (f *File) Validate() error {
	if f.Filename == "" {
		return ErrMissingFilename
	}

	if f.FileManager == nil {
		return ErrMissingFileManager
	}

	if f.IOWriter == nil {
		return ErrMissingIOWriter
	}

	return nil
}

func (fd *FileDelegate) ManageFile(filename string) (*os.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (iowd *IOWriteDelegate) OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, data)
	return err
}
