package event

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"
)

const TO_MILI_FROM_NANO = 1000

type Event struct {
	Syscall string // Syscall name
	PID     uint32
	Comm    string
	UID     uint32
	User    string
	File    string
	Retval  int64
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
	syscall_name := getSyscallFromCode(syscall_code)

	// Get PID and UID
	pid := binary.LittleEndian.Uint32(marshd[4:8])
	uid := binary.LittleEndian.Uint32(marshd[8:12])

	// Find the username
	username := getUsernameFromUid(uid)

	// GEt Commname(LEN = 16) and Filename (LEN = 64)
	comm := string(marshd[12:28])
	if strings.Contains(comm, "monitor") {
		// We don't want to trace this process
		return Event{}
	}
	filename := string(marshd[28:92])

	// Timestamp (last bytes)
	ts_enter := binary.LittleEndian.Uint64(marshd[96:104])
	ts_exit := binary.LittleEndian.Uint64(marshd[104:112])

	time_spent_ms := (float64(ts_exit) - float64(ts_enter)) / TO_MILI_FROM_NANO

	ts := time.Now()

	retval, _ := binary.Varint(marshd[112:116])

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

func getSyscallFromCode(b byte) string {
	switch b {
	case 'o':
		return "Syscall Openat"
	case 'r':
		return "Syscall Read"
	case 'w':
		return "Syscall sWrite"
	default:
		return "None"
	}
}

func getUsernameFromUid(uid uint32) string {
	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func PrintBytesHex(rawsample []byte) {

	fmt.Print("[")
	for i := 0; i < len(rawsample); i++ {
		if i == len(rawsample) {
			fmt.Printf("0x%x", rawsample[i])
		}
		fmt.Printf("0x%x, ", rawsample[i])
	}
	fmt.Print("]\n")
	os.Exit(1)
}
