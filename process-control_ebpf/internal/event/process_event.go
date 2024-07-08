package event

import (
	"encoding/binary"

	"example.com/process_control/utils"
)

// This struct defines the information of a process event
// Such as PPID, or Action (clone, exec, fork)
type Event struct {
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	Comm       string
	ParentComm string
	Action     string
}

func UnmarshallEvent(marshd []byte) Event {
	utils.PrintBytesHex(marshd)

	evt := Event{}

	evt.Pid = binary.LittleEndian.Uint32(marshd[0:4])
	evt.Ppid = binary.LittleEndian.Uint32(marshd[4:8])
	evt.Uid = binary.LittleEndian.Uint32(marshd[8:12])
	evt.Gid = binary.LittleEndian.Uint32(marshd[12:16])

	evt.Comm = string(marshd[16:32])
	evt.ParentComm = string(marshd[32:48])
	// TODO: Unmarshall binary to struct

	return evt
}
