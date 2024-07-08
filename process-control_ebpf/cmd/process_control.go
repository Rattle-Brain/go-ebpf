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

		fmt.Printf("User %s performed %s action\n", evt.Comm, evt.Action)
	}
}
