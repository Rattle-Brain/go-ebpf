package event

import (
	"encoding/binary"
	"fmt"
	"os/user"
	"strings"
	"time"
)

type Event struct {
	Syscall string // Syscall name
	//	Entering  bool   // Entering (0) or exiting (1)
	PID       uint32
	Commname  string
	UID       uint32
	Username  string
	Filename  string
	Retval    int64
	Timestamp uint64
}

/*
Extracts information from byte array and transforms it into an event
Works for the entry event
*/
func UnmarshallEntryEvent(marshd []byte) Event {
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
	timestamp := binary.BigEndian.Uint64(marshd[92:100])

	ts := time.Unix(0, int64(timestamp))

	// Create the event struct and fill it up
	evt := Event{
		Syscall:   syscall_name,
		PID:       pid,
		Commname:  comm,
		UID:       uid,
		Username:  username,
		Filename:  filename,
		Retval:    -200,
		Timestamp: timestamp,
	}

	// Print for goo measure, will be removed
	fmt.Printf("ENTERING Syscall: %s, PID: %d, UID: %d, USER: %s, COMM: %s, FILENAME: %s, TIME: %s\n", syscall_name,
		pid, uid, username, comm, filename, ts.Format(time.RFC3339Nano))

	return evt
}

/*
Extracts information from byte array and transforms it into an event
Works for the exit event
*/
func UnmarshallExitEvent(marshd []byte) Event {
	// Same gimmick here

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

	// Timestamp (last bytes)
	timestamp := binary.BigEndian.Uint64(marshd[28:36])
	ts := time.Unix(0, int64(timestamp))

	retval, _ := binary.Varint(marshd[36:44])

	evt := Event{
		Syscall:   syscall_name,
		PID:       pid,
		Commname:  comm,
		UID:       uid,
		Username:  username,
		Filename:  "",
		Retval:    retval,
		Timestamp: timestamp,
	}
	// Print for goo measure, will be removed
	fmt.Printf("EXITING Syscall: %s, PID: %d, UID: %d, USER: %s, COMM: %s, RETVAL: %d, TIME: %s\n", syscall_name,
		pid, uid, username, comm, retval, ts.Format(time.RFC3339Nano))

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
