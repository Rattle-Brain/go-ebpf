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

		fmt.Printf("Process %s (USER: %s // GROUP: %s) %s into %s (USER: %s // GROUP: %s)\n", evt.ParentComm,
			evt.ParentOwner, evt.ParentGroup, evt.Action, evt.Comm, evt.TaskOwner, evt.TaskGroup)
	}
}
