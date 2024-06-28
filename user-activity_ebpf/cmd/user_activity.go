package main

import (
	"fmt"

	"example.com/user-activity/internal/action"
	"example.com/user-activity/internal/probe"
)

func main() {

	event_channel := make(chan action.Action, 10)

	go probe.Run(event_channel)

	for {

		act := <-event_channel

		fmt.Printf("User %s performed %s action\n", act.User, act.ActionName)
	}
}
