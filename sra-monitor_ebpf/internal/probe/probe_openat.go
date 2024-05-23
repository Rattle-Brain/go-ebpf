package probe

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"example.com/sra-monitor/internal/event"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// Constants defined
const LEN_FILENAME int = 64
const LEN_COMM int = 16

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang openat ../../bpf/openat_monitor.bpf.c -- -I/usr/include/linux/bpf.h

// type DataEnter struct {
// 	//Syscall_code byte
// 	PID         uint32
// 	UID         uint32
// 	Comm        [LEN_COMM]byte
// 	Filename    [LEN_FILENAME]byte
// 	Timestamp   uint64
// 	SyscallCode byte
// }

// type DataExit struct {
// 	PID         uint32
// 	UID         uint32
// 	Comm        [LEN_COMM]byte
// 	Timestamp   uint64
// 	Retval      int32
// 	SyscallCode byte
// }

func Run() {
	fmt.Println("Setting memory limit...")
	setLimit()
	fmt.Println("Done!")

	// Create monitor ebpf objects and load them
	objs := initializeBPFObjects()
	defer objs.Close() // Need to be closed after

	// Attach tracepoint to sys_enter_open
	fmt.Println("\nAttaching tracepoints...")
	tpEnterOpen := attachTracepoint("sys_enter_openat", objs.openatPrograms.TraceEnterOpen)
	defer tpEnterOpen.Close()

	// Attach tracepoint to sys_exit_open
	tpExitOpen := attachTracepoint("sys_exit_openat", objs.openatPrograms.TraceExitOpen)
	defer tpExitOpen.Close()
	/*
		// Attach tracepoint to sys_enter_open
		tpEnterRead := attachTracepoint("sys_enter_read", objs.monitorPrograms.TraceEnterRead)
		defer tpEnterRead.Close()

		// Attach tracepoint to sys_exit_open
		tpExitRead := attachTracepoint("sys_exit_read", objs.monitorPrograms.TraceExitRead)
		defer tpExitRead.Close()

		// Attach tracepoint to sys_enter_open
		tpEnterWrite := attachTracepoint("sys_enter_write", objs.monitorPrograms.TracepointEnterWrite)
		defer tpEnterWrite.Close()

		// Attach tracepoint to sys_exit_open
		tpExitWrite := attachTracepoint("sys_exit_write", objs.monitorPrograms.TraceExitWrite)
		defer tpExitWrite.Close()
	*/
	fmt.Println("Done!")

	/**
	TODO:
		Theres a lot of tracepoints defined in bpf/code.bpf.c that are not being used for now.
		I will add them later down the line. For now, I'll check that the program works
		correctly with just enter and exit open syscall.
	*/

	// Create a reader able to extract info from the map
	rd := createRingBufferReader(objs)
	defer rd.Close()

	fmt.Println("\neBPF programs attached. Waiting for events...")
	readEvents(rd)
}

/*
Loops indefinetly to read events from the bpf map as they happen.
*/
func readEvents(rd *perf.Reader) {
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("Reading from ring buffer: %v", err)
			continue
		}

		//var evt DataEnter
		//var evtExit DataExit
		buf := bytes.NewBuffer(record.RawSample)

		// Determine the type of event based on the size of the record
		if buf.Len() == 188 {
			event.UnmarshallOpenatEvent(record.RawSample)
		} else {
			log.Printf("unknown event size: %d", buf.Len())
		}
	}
}

/*
Initializes the bpf objects, loading them into userspace
returns bpf objects
*/
func initializeBPFObjects() openatObjects {
	objs := openatObjects{}
	fmt.Println("\nLoading eBPF objects...")
	if err := loadOpenatObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
		os.Exit(-1)
	}
	fmt.Println("Done!")
	return objs
}

/*
Attaches a tracepoint given the name of the syscall and the
ebpf program
*/
func attachTracepoint(syscall_name string, prog *ebpf.Program) link.Link {
	tracepoint, err := link.Tracepoint("syscalls", syscall_name, prog, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint sys_enter_open: %v", err)
		os.Exit(-2)
	}
	return tracepoint
}

/*
Attempts to create a Reader to extract data from the ring buffer
*/
func createRingBufferReader(objs openatObjects) *perf.Reader {
	fmt.Println("\nCreating reader...")
	rd, err := perf.NewReader(objs.FileEventMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("Opening ring buffer reader: %v", err)
		os.Exit(-4)
	}
	fmt.Println("Done!")
	return rd
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
