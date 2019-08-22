package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type FileHandler interface {
	Handle(data string) error
}

type File struct {
	Filename    string
	FileManager FileManager
}

func NewFile(filename string) *File {
	return &File{
		Filename:    filename,
		FileManager: &FileDelegate{},
	}
}

func (f *File) Handle(data string) error {
	file, err := f.FileManager.ManageFile(f.Filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	return OutputToWriter(data, w)
}

type FileManager interface {
	ManageFile(filename string) (*os.File, error)
}

type FileDelegate struct{}

func (fd *FileDelegate) ManageFile(filename string) (*os.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, data)
	return err
}
