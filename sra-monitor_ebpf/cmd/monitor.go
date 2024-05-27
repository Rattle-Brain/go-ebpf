package main

import (
	"fmt"

	"example.com/sra-monitor/internal/event"
	probe_openat "example.com/sra-monitor/internal/probe/sys_openat"
	probe_write "example.com/sra-monitor/internal/probe/sys_write"
)

func main() {

	// We create a channel to read from
	event_channel := make(chan event.Event)

	// Launch goroutines to execute code (read events)
	go probe_openat.Run(event_channel)
	go probe_write.Run(event_channel)

	// Infinite loop to read from channel and print information
	for {
		evt := <-event_channel

		fmt.Printf("%s %s run %s (PID: %d) executed %s in %d ms on file %s. Returned: %d\n", evt.Date,
			evt.User, evt.Comm, evt.PID, evt.Syscall, evt.Latency, evt.File, evt.Retval)
	}
}
