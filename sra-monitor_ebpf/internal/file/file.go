package file

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"example.com/sra-monitor/dbg"
	"example.com/sra-monitor/internal/event"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var SFILES_TXT string = "LINUX-SENSITIVE-FILES.txt" // Modify this if you want another file
var OUTPUT_LOG string = "monitor.log"

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
Obtains a list of sensitive files to observe. Returns a slice with the files or
an empty slice if something failed while opening and processing the file
*/
func RetrieveSensitiveFilesList(name string) []string {

	dbg.DebugPrintfExtra("Loading files...\n")
	file, err := OpenFileRead(name)
	if err != nil {
		dbg.DebugPrintf("File %s could not be opened. Permissions?", name)
		return ([]string{})
	}
	defer file.Close()

	var sensitive_files []string
	scn := bufio.NewScanner(file)
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		// Ignore comments and empty lines
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// Ignore invalid lines and print debug message
		if line[0] != '/' {
			dbg.DebugPrintf("DEBUG: Ignored line '%s' as it does not start with '/' (root directory)\n", line)
			continue
		}
		sensitive_files = append(sensitive_files, line)
		dbg.DebugPrintfExtra("Formatted line succesfully: (%s)\n", line)
	}

	if err := scn.Err(); err != nil {
		dbg.DebugPrintf("Scanner failure %s\n", err)
		return ([]string{})
	}

	return sensitive_files

}

func WatchFile(filename string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Printf("Error creating watcher: %v\n", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(filename)
	if err != nil {
		fmt.Printf("Error adding file to watcher: %v\n", err)
		return
	}

	for {
		select {
		case evt, ok := <-watcher.Events:
			if !ok {
				return
			}
			if evt.Op&fsnotify.Write == fsnotify.Write {
				temp := RetrieveSensitiveFilesList(filename)
				if len(temp) > 0 {
					dbg.DebugPrintfExtra("Applying changes")
					event.SFILES = temp
					continue
				} else if len(temp) == 0 {
					dbg.DebugPrintfExtra("File contains no paths to observe. Change not applied")
					continue
				} else {
					dbg.DebugPrintln("File length is below 0. How did you do this?")
					continue
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Error in file watcher: %v\n", err)
		}
	}
}

/*
Appends data to an opened file using logrus.
The data is received from the pkt parameter, which contains the
unmarshalled information of the intercepted Packet
*/
func AppendToFile(file *os.File, evt event.Event) error {
	if file == nil {
		return fmt.Errorf("pointer to file is nil (%p)", file)
	}
	if evt == (event.Event{}) {
		return fmt.Errorf("cannot parse empty event")
	}

	// Create a new logrus logger
	logger := logrus.New() // Only log the warning severity or above.
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = file

	logger.SetFormatter(&logrus.TextFormatter{
		DisableColors:    false,
		DisableTimestamp: true,
		ForceQuote:       true,
	})

	entry := logger.WithFields(logrus.Fields{
		"Date":         evt.Date,
		"User":         evt.User,
		"Proccess":     evt.Comm,
		"PID":          evt.PID,
		"Syscall":      evt.Syscall,
		"Latency (ms)": evt.Latency,
		"File":         evt.File,
		"Return value": evt.Retval,
	})

	switch strings.ToLower(evt.Syscall)[0] {
	case 'o':
		logOpenatInfo(evt, entry)
	case 'w':
		logWriteInfo(evt, entry)
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

func logOpenatInfo(evt event.Event, entry *logrus.Entry) {
	if evt.Retval >= 0 {
		if strings.Contains(evt.Comm, "DNS Resolver") {
			entry.Info()
		} else {
			entry.Debug()
		}
	} else {
		entry.Error()
	}
}

func logWriteInfo(evt event.Event, entry *logrus.Entry) {
	if strings.EqualFold(evt.User, "root") {
		entry.Warning()
	} else {
		entry.Warning()
	}
}
