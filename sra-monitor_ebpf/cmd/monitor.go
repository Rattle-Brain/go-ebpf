package main

import "golang.org/x/sys/unix"

type DataEnter struct {
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Filename  [unix.NAME_MAX]byte
	Timestamp uint64
}

type DataExit struct {
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Timestamp uint64
	Retval    int32
}
