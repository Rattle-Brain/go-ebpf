package main

import (
	"fmt"

	"example.com/process_control/internal/event"
	"example.com/process_control/internal/probe"
)

func main() {

	event_channel := make(chan event.Event, 10)

	go probe.Run(event_channel)

	for {

		evt := <-event_channel

		fmt.Printf("Task %s with parent %s performed action %s\n", evt.Comm, evt.ParentComm, evt.Action)
	}
}
