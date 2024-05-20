package event

import "encoding/binary"

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
	pid := binary.LittleEndian.Uint32(marshd[1:5])
	uid := binary.LittleEndian.Uint32(marshd[5:9])
	comm := marshd[9:25]
	filename := marshd[25:89]
	timestamp := binary.LittleEndian.Uint64(marshd[89:97])

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
