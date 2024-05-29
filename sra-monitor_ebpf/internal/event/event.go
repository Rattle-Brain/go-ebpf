package event

import (
	"encoding/binary"
	"strings"
	"time"

	"example.com/sra-monitor/utils"
)

const NS_TO_MS = 1000

var SFILES []string

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

// Interface. Selects what event to unmarshall based on 1st char
// and returns an event filled or empty
func UnmarshallEvent(marshd []byte) Event {

	if len(marshd) == 188 && marshd[0] == 'o' {
		return unmarshallOpenatEvent(marshd)
	} else if len(marshd) == 68 && marshd[0] == 'w' {
		return unmarshallWriteEvent(marshd)
	} else {
		return Event{}
	}
}

/*
Parses a byte array transforming it into an Openat Syscall Event
*/
func unmarshallOpenatEvent(marshd []byte) Event {
	//First we need to parse the events. Since most of the time the
	// Automatic process wil not do it properly with the offsets
	// We need to do it manually like so.

	// I put this first to avoid further unmarshalling if filename is not observable
	filename := string(marshd[28:156])
	if !isInList(filename, SFILES) {
		return Event{}
	}

	// Initial byte for opcode to string
	syscall_code := marshd[0]
	syscall_name := utils.GetSyscallFromCode(syscall_code)

	// Get PID and UID
	pid := binary.LittleEndian.Uint32(marshd[4:8])
	uid := binary.LittleEndian.Uint32(marshd[8:12])

	// Find the username
	username := utils.GetUsernameFromUid(uid)

	// Get Commname(LEN = 16) and Filename (LEN = 128)
	comm := string(marshd[12:28])
	if strings.Contains(comm, "monitor") {
		// We don't want to trace this process
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
		Comm:    strings.Trim(comm, "\x00"),
		UID:     uid,
		User:    username,
		File:    strings.Trim(filename, "\x00"),
		Retval:  retval,
		Latency: uint64(time_spent_ms),
		Date:    ts.Format(time.RFC1123),
	}

	return evt
}

func unmarshallWriteEvent(marshd []byte) Event {
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

	fd := binary.LittleEndian.Uint64(marshd[32:40])
	filename := utils.GetFilePath(pid, fd)
	// Verifies that filename is in list, otherwise, we don't observe
	if !isInList(filename, SFILES) {
		return Event{}
	}

	// Timestamp (last bytes)
	ts_enter := binary.LittleEndian.Uint64(marshd[40:48])
	ts_exit := binary.LittleEndian.Uint64(marshd[48:56])

	time_spent_ms := (float64(ts_exit) - float64(ts_enter)) / NS_TO_MS

	ts := time.Now()

	retval := int32(binary.LittleEndian.Uint32(marshd[56:60]))

	// Create the event struct and fill it up
	evt := Event{
		Syscall: syscall_name,
		PID:     pid,
		Comm:    strings.Trim(comm, "\x00"),
		UID:     uid,
		User:    username,
		File:    strings.Trim(filename, "\x00"),
		Retval:  retval,
		Latency: uint64(time_spent_ms),
		Date:    ts.Format(time.RFC1123),
	}

	//utils.PrintBytesHex(marshd)
	return evt
}

func isInList(filename string, sfiles []string) bool {
	for i := 0; i < len(sfiles); i++ {
		if strings.Contains(filename, sfiles[i]) {
			return true
		}
	}
	return false
}
