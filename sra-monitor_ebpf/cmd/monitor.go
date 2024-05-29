package main

import (
	"fmt"
	"os"

	"example.com/sra-monitor/dbg"
	"example.com/sra-monitor/internal/event"
	"example.com/sra-monitor/internal/file"
	probe_openat "example.com/sra-monitor/internal/probe/sys_openat"
	probe_write "example.com/sra-monitor/internal/probe/sys_write"
)

func main() {

	log, err := file.OpenFileWrite(file.OUTPUT_LOG)
	if err != nil {
		fmt.Printf("Could not open LOG file. Creating one...\n")
		err = file.CreateFile(file.OUTPUT_LOG)
		if err != nil {
			fmt.Printf("Could not create LOG file. Aborting...")
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

	// Infinite loop to read from channel and print information
	for {
		evt := <-event_channel

		dbg.DebugPrintf("%s %s run %s (PID: %d) executed %s in %d ms on file %s. Returned: %d\n", evt.Date,
			evt.User, evt.Comm, evt.PID, evt.Syscall, evt.Latency, evt.File, evt.Retval)

		// Attempt to append entry to file
		err := file.AppendToFile(log, evt)
		if err != nil {
			dbg.DebugPrintf("Could not event append to file\n")
			continue
		}
	}
}
