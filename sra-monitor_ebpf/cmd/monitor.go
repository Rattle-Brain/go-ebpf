package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang monitor ../bpf/code.bpf.c -- -I/usr/include/linux/bpf.h

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

func setLimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("Failed to set memory limit")
		os.Exit(-5)
	}
}

func getUsernameFromUid(uid uint32) string {
	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func main() {
	fmt.Println("Setting memory limit...")
	setLimit()
	fmt.Println("Done!")

	// Create monitor ebpf objects
	objs := monitorObjects{}

	// And load them into userspace (check for errors)
	fmt.Println("\nLoading eBPF objects...")
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
		os.Exit(-1)
	}
	defer objs.Close() // Need to be closed after
	fmt.Println("Done!")

	// Attach tracepoint to sys_enter_open
	fmt.Println("\nAttaching tracepoints...")
	tpEnterOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.monitorPrograms.TraceEnterOpen, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint sys_enter_open: %v", err)
		os.Exit(-2)
	}
	defer tpEnterOpen.Close()

	// Attach tracepoint to sys_exit_open
	tpExitOpen, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.monitorPrograms.TraceExitOpen, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint sys_exit_open: %v", err)
		os.Exit(-3)
	}
	defer tpExitOpen.Close()
	fmt.Println("Done!")

	/**
	TODO:
		Theres a lot of tracepoints defined in bpf/code.bpf.c that are not being used for now.
		I will add them later down the line. For now, I'll check that the program works
		correctly with just enter and exit open syscall.
	*/

	// Create a reader able to extract info from the map
	fmt.Println("\nCreating reader...")
	rd, err := perf.NewReader(objs.FileEventMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("Opening ring buffer reader: %v", err)
		os.Exit(-4)
	}
	defer rd.Close()
	fmt.Println("Done!")

	fmt.Println("\neBPF programs attached. Waiting for events...")
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("Reading from ring buffer: %v", err)
			continue
		}

		var evt DataEnter
		var evtExit DataExit
		buf := bytes.NewBuffer(record.RawSample)

		// Determine the type of event based on the size of the record
		if buf.Len() == 100 {
			err = binary.Read(buf, binary.LittleEndian, &evt)
			if err != nil {
				log.Printf("parsing ring buffer event: %v", err)
				continue
			}

			username := getUsernameFromUid(evt.UID)
			timestamp := time.Unix(0, int64(evt.Timestamp))

			fmt.Printf("ENTER: Time: %s, PID: %d, UID: %d, User: %s, Comm: %s, Filename: %s\n",
				timestamp.Format(time.RFC3339), evt.PID, evt.UID, username, string(evt.Comm[:]), string(evt.Filename[:]))
		} else if buf.Len() == 44 {
			err = binary.Read(buf, binary.LittleEndian, &evtExit)
			if err != nil {
				log.Printf("parsing ring buffer event: %v", err)
				continue
			}

			username := getUsernameFromUid(evtExit.UID)
			timestamp := time.Unix(0, int64(evtExit.Timestamp))

			fmt.Printf("EXIT: Time: %s, PID: %d, UID: %d, User: %s, Comm: %s, Retval: %d\n",
				timestamp.Format(time.RFC3339), evtExit.PID, evtExit.UID, username, string(evtExit.Comm[:]), evtExit.Retval)
		} else {
			log.Printf("unknown event size: %d", buf.Len())
		}
	}
}
