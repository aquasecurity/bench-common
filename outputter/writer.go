package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type FileWriter interface {
	Write(data string) error
}

func File struct {
	Filename string
	FileManager FileManager
}

func NewFile(filename string) *File {
	return &File{
		Filename: filename,
		FileManager: &FileDelegate{},
	}
}

func (f *File) Write(data) error {
	f, err := f.FileManager.ManageFile(f.filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return OutputToWriter(data, bufio.NewWriter(f))
}

type FileManager interface {
	ManageFile(filename string) (*io.File, error)
}

type FileDelegate struct {}

func (fd *FileDelegate) ManageFile(filename string) (*io.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, output)
	if err != nil {
		return err
	}
	return w.Flush()
}
