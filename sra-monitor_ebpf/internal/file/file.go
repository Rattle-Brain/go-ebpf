package file

import (
	"encoding/csv"
	"fmt"
	"os"

	"example.com/sra-monitor/internal/event"
)

/*
Creates a new file, and adds a header to knwo what each field is
*/
func CreateFile(name string) error {
	header := []string{"Date", "Username", "Proccess", "PID", "Syscall", "Latency", "File", "Return Value"}
	file, err := os.Create(name)
	if err != nil {
		fmt.Printf("Error creating a new file. Permissons?\n")
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write(header)
	defer writer.Flush()

	return nil
}

/*
Opens an existing file to write on, or returns error if it can't
*/
func OpenFileWrite(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

/*
Opens an existing file to read from, or returns error if it can't
*/
func OpenFileRead(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

/*
Obtains a list of sensitive files to observe
*/
func RetrieveSensitiveFilesList(name string) []string {

	return []string{"", ""}
}

/*
Appends data to an opened file. The data is received from the pkt parameter,
which contains the unmarshalled information of the intercepted Packet
*/
func AppendToFile(file *os.File, evt event.Event) error {

	writer := csv.NewWriter(file)
	defer writer.Flush()

	date := evt.Date
	user := evt.User
	comm := evt.Comm
	pid := fmt.Sprintf("%d", evt.PID)
	syscall := evt.Syscall
	latency := fmt.Sprintf("%d", evt.Latency)
	fname := evt.File
	retval := string(evt.Retval)

	data := []string{date, user, comm, pid, syscall, latency, fname, retval}

	err := writer.Write(data)
	if err != nil {
		fmt.Printf("Error writing data to file\n")
		return err
	}

	return nil
}

/*
Closes a file after every byte has ben flushed out of the buffer of
the writer.
*/
func CloseFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	err := file.Close()
	if err != nil {
		return err
	}
	return nil
}
