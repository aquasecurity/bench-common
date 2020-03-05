package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type fileHandler interface {
	Handle(data string) error
}

type file struct {
	Filename string
}

type ioWriter interface {
	OutputToWriter(data string, w io.Writer) error
}

func newFile(filename string) *file {
	return &file{
		Filename: filename,
	}
}

func (f *file) Handle(data string) error {
	var w io.Writer
	var err error
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
	_, err = fmt.Fprintln(w, data)

	return err
}
