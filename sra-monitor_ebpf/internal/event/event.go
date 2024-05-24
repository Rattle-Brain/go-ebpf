package event

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"example.com/sra-monitor/utils"
)

const NS_TO_MS = 1000

type Event struct {
	Syscall string // Syscall name
	PID     uint32
	Comm    string
	UID     uint32
	User    string
	File    string
	Retval  int32
	Latency uint64
	Date    string
}

/*
Parses a byte array transforming it into an Openat Syscall Event
*/
func UnmarshallOpenatEvent(marshd []byte) Event {
	//First we need to parse the events. Since most of the time the
	// Automatic process wil not do it properly with the offsets
	// We need to do it manually like so.

	// Initial byte for opcode to string
	syscall_code := marshd[0]
	syscall_name := utils.GetSyscallFromCode(syscall_code)

	// Get PID and UID
	pid := binary.LittleEndian.Uint32(marshd[4:8])
	uid := binary.LittleEndian.Uint32(marshd[8:12])

	// Find the username
	username := utils.GetUsernameFromUid(uid)

	// Get Commname(LEN = 16) and Filename (LEN = 64)
	comm := string(marshd[12:28])
	if strings.Contains(comm, "monitor") {
		// We don't want to trace this process
		return Event{}
	}

	filename := string(marshd[28:156])
	if strings.EqualFold(filename, "") {
		return Event{}
	}

	// Timestamp (last bytes)
	ts_enter := binary.LittleEndian.Uint64(marshd[160:168])
	ts_exit := binary.LittleEndian.Uint64(marshd[168:176])

	time_spent_ms := (float64(ts_exit) - float64(ts_enter)) / NS_TO_MS

	ts := time.Now()

	retval := int32(binary.LittleEndian.Uint32(marshd[176:180]))

	// Create the event struct and fill it up
	evt := Event{
		Syscall: syscall_name,
		PID:     pid,
		Comm:    comm,
		UID:     uid,
		User:    username,
		File:    filename,
		Retval:  retval,
		Latency: uint64(time_spent_ms),
		Date:    ts.Format(time.RFC1123),
	}

	// Print for goo measure, will be removed
	fmt.Printf("%s %s executed %s (PID: %d) in %d ms on file %s. Returned: %d\n", evt.Date,
		evt.User, evt.Comm, evt.PID, evt.Latency, evt.File, evt.Retval)

	return evt
}
