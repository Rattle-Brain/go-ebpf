package event

import (
	"encoding/binary"
	"fmt"
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

	syscall_code := marshd[0]
	syscall_name := getSyscallFromCode(syscall_code)
	pid := binary.LittleEndian.Uint32(marshd[4:8])
	uid := binary.LittleEndian.Uint32(marshd[8:12])
	comm := string(marshd[12:28])
	filename := string(marshd[28:92])
	timestamp := binary.BigEndian.Uint64(marshd[92:108])
	ts := time.Unix(0, int64(timestamp))

	fmt.Printf("Syscall: %s, PID: %d, UID: %d, COMM: %s, FILENAME: %s, TIME: %s\n", syscall_name,
		pid, uid, comm, filename, ts.Format(time.RFC3339Nano))

	return Event{}
}

func UnmarshallExit(marshd []byte) Event {

	return Event{}
}

func getSyscallFromCode(b byte) string {
	switch b {
	case 'o':
		return "Syscall_Openat"
	case 'r':
		return "Syscall_Read"
	case 'w':
		return "Syscall_Write"
	default:
		return "None"
	}
}
