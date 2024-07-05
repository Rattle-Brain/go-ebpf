package probe

import (
	"log"
	"os"

	"example.com/user-activity/dbg"
	"example.com/user-activity/internal/event"
	"example.com/user-activity/utils"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang p_control ../../bpf/process_control.bpf.c -- -I/usr/include/linux/bpf.h

func Run(evts chan event.Event) {
	dbg.DebugPrintlnExtra("Setting memory limit...")
	utils.SetMemLimit()
	dbg.DebugPrintlnExtra("Done!")

	// Create monitor ebpf objects and load them
	objs := initializeBPFObjects()
	defer objs.Close() // Need to be closed after

	// Attach tracepoint to sys_enter_clone
	dbg.DebugPrintlnExtra("\nAttaching Syscall Write tracepoints...")
	tpClone := utils.AttachTracepoint("sys_enter_clone", objs.p_controlPrograms.TraceClone)
	defer tpClone.Close()

	// Attach tracepoint to sys_enter_execve
	tpExecve := utils.AttachTracepoint("sys_enter_execve", objs.p_controlPrograms.TraceExecve)
	defer tpExecve.Close()

	// Attach tracepoint to sys_enter_fork
	tpFork := utils.AttachTracepoint("sys_enter_fork", objs.p_controlPrograms.TraceFork)
	defer tpFork.Close()

	dbg.DebugPrintlnExtra("Done!")

	// Create a reader able to extract info from the map
	rd := createRingBufferReader(objs)
	defer rd.Close()

	dbg.DebugPrintlnExtra("\neBPF Write programs attached. Waiting for events...")
	readEvents(rd, evts)
}

/*
Loops indefinetly to read events from the bpf map as they happen.
*/
func readEvents(rd *perf.Reader, acts chan event.Event) {
	for {
		record, err := rd.Read()
		if err != nil {
			dbg.DebugPrintf("ERROR: Reading from ring buffer: %v", err)
			continue
		}

		// Determine the type of event based on the size of the record
		act := event.UnmarshallEvent(record.RawSample)
		if act != (event.Event{}) {
			acts <- event.UnmarshallEvent(record.RawSample)
		}
	}
}

/*
Initializes the bpf objects, loading them into userspace
returns bpf objects
*/
func initializeBPFObjects() p_controlObjects {
	objs := p_controlObjects{}
	dbg.DebugPrintlnExtra("\nLoading eBPF objects...")
	if err := loadP_controlObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
		os.Exit(-1)
	}
	dbg.DebugPrintlnExtra("Done!")
	return objs
}

/*
Attempts to create a Reader to extract data from the ring buffer
*/
func createRingBufferReader(objs p_controlObjects) *perf.Reader {
	dbg.DebugPrintlnExtra("\nCreating reader...")
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Opening ring buffer reader: %v", err)
		os.Exit(-4)
	}
	dbg.DebugPrintlnExtra("Done!")
	return rd
}
