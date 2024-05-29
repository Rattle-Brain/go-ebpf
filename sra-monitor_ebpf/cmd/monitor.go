package main

import (
	"flag"
	"fmt"
	"os"

	"example.com/sra-monitor/dbg"
	"example.com/sra-monitor/internal/event"
	"example.com/sra-monitor/internal/file"
	probe_openat "example.com/sra-monitor/internal/probe/sys_openat"
	probe_write "example.com/sra-monitor/internal/probe/sys_write"
)

var verbose bool
var extraVerbose bool

func main() {

	// Establish flags for the program to use
	flag.BoolVar(&verbose, "v", false, "Enable verbose mode")
	flag.BoolVar(&extraVerbose, "vv", false, "Enable extra verbose mode")
	flag.StringVar(&file.OUTPUT_LOG, "L", "monitor.log", "Specific Log file name. If empty -> monitor.log")
	flag.StringVar(&file.SFILES_TXT, "F", "LINUX-SENSITIVE-FILES.txt", "Sensitive-file-list text file. If empty it'll attempt to read from \"LINUX-SENSITIVE-FILES.txt\"")
	flag.Parse()

	// Send the variables to where they're needed
	if !verbose {
		// Message so the user knows to expect no messages
		fmt.Printf("Starting monitor...\nOnly errors will be shown in console.\nEnable verbose mode to see more messages")
	}
	dbg.SetVerboseMode(verbose)
	dbg.SetExtraVerboseMode(extraVerbose)

	// Now we open or create a log file to output info to
	log, err := file.OpenFileWrite(file.OUTPUT_LOG)
	if err != nil {
		dbg.DebugPrintf("Could not open LOG file. Creating one...\n")
		err = file.CreateFile(file.OUTPUT_LOG)
		if err != nil {
			dbg.DebugPrintf("Could not create LOG file. Aborting...")
			os.Exit(-11)
		}
		log, _ = file.OpenFileWrite(file.OUTPUT_LOG)
	}
	defer file.CloseFile(log)

	// We create a channel to read from
	event_channel := make(chan event.Event)

	// Launch goroutines to execute code (read events)
	go probe_openat.Run(event_channel)
	go probe_write.Run(event_channel)

	// Goroutine to watch the file and update Sensitive Resources updates
	go file.WatchFile(file.SFILES_TXT)

	// And finally let's initialize the information exisiting in the SRA file
	event.SFILES = file.RetrieveSensitiveFilesList(file.SFILES_TXT)

	// Infinite loop to read from channel and print information
	for {
		evt := <-event_channel
		if err != nil {
			fmt.Printf("Error retrieving sensitive files list: %v\n", err)
			return
		}
		dbg.DebugPrintf("%s %s run %s (PID: %d) executed %s in %d ms on file %s. Returned: %d\n", evt.Date,
			evt.User, evt.Comm, evt.PID, evt.Syscall, evt.Latency, evt.File, evt.Retval)

		// Attempt to append entry to file
		err = file.AppendToFile(log, evt)
		if err != nil {
			dbg.DebugPrintf("Could not event append to file\n")
			continue
		}
	}
}
