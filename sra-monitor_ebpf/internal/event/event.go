package event

import (
	"encoding/binary"
	"fmt"
	"os/user"
	"time"
)

type Event struct {
	Syscall string // Syscall name
	//	Entering  bool   // Entering (0) or exiting (1)
	PID       int32
	Username  string
	Filename  string
	Retval    int32
	Timestamp uint64
}

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
	filename := string(marshd[28:92])

	// Timestamp (last bytes)
	timestamp := binary.BigEndian.Uint64(marshd[92:108])
	ts := time.Unix(0, int64(timestamp))

	fmt.Printf("Syscall: %s, PID: %d, UID: %d, USER: %s, COMM: %s, FILENAME: %s, TIME: %s\n", syscall_name,
		pid, uid, username, comm, filename, ts.Format(time.RFC3339Nano))

	return Event{}
}

func UnmarshallExit(marshd []byte) Event {

	return Event{}
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
