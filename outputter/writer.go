package outputter

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func OutputToFile(data, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	return OutputToWriter(data, w)
}

func OutputToWriter(data string, w io.Writer) error {
	_, err := fmt.Fprintln(w, output)
	if err != nil {
		return err
	}
	return w.Flush()
}
