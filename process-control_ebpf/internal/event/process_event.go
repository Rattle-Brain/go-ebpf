package event

import (
	"encoding/binary"
	"fmt"

	"example.com/process_control/utils"
)

// This struct defines the information of a process event
// Such as PPID, or Action (clone, exec, fork)
type Event struct {
	Ppid        uint32
	Puid        uint32
	Pgid        uint32
	Pid         uint32
	Uid         uint32
	Gid         uint32
	ParentOwner string
	ParentGroup string
	ParentComm  string
	TaskOwner   string
	TaskGroup   string
	Comm        string
	Action      string
}

func UnmarshallEvent(marshd []byte) Event {
	// utils.PrintBytesHex(marshd)
	evt := Event{}

	if len(marshd) != 60 {
		fmt.Printf("Error parsing event. Incorrect length. Omitting...\n")
		return Event{}
	}
	// Parse parent process info
	evt.Ppid = binary.LittleEndian.Uint32(marshd[0:4])
	evt.Puid = binary.LittleEndian.Uint32(marshd[4:8])
	evt.Pgid = binary.LittleEndian.Uint32(marshd[8:12])

	// Parse process info
	evt.Pid = binary.LittleEndian.Uint32(marshd[12:16])
	evt.Uid = binary.LittleEndian.Uint32(marshd[16:20])
	evt.Gid = binary.LittleEndian.Uint32(marshd[20:24])

	// Parse parent process strings (owner and group)
	evt.ParentOwner = utils.GetUsernameFromUid(evt.Puid)
	evt.ParentGroup = utils.GetGroupnameFromGid(evt.Pgid)

	// parse process strings (owner and groupd)
	evt.TaskOwner = utils.GetUsernameFromUid(evt.Uid)
	evt.TaskGroup = utils.GetGroupnameFromGid(evt.Gid)

	// Parse comms
	evt.Comm = string(marshd[24:40])
	evt.ParentComm = string(marshd[40:56])

	// Parse action (clone, execve, fork...)
	evt.Action = utils.GetSyscallFromCode(marshd[56])

	return evt
}
