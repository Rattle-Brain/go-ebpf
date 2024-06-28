package probe

import (
	"log"
	"os"

	"example.com/user-activity/dbg"
	"example.com/user-activity/internal/action"
	"example.com/user-activity/utils"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang user_actions ../../bpf/user_monitor.bpf.c -- -I/usr/include/linux/bpf.h

func Run(evts chan action.Action) {
	dbg.DebugPrintlnExtra("Setting memory limit...")
	utils.SetMemLimit()
	dbg.DebugPrintlnExtra("Done!")

	// Create monitor ebpf objects and load them
	objs := initializeBPFObjects()
	defer objs.Close() // Need to be closed after

	// Attach tracepoint to sys_enter_open
	dbg.DebugPrintlnExtra("\nAttaching Syscall Write tracepoints...")
	tpEnterWrite := utils.AttachTracepoint("sys_enter_setuid", objs.user_actionsPrograms.TraceLogin)
	defer tpEnterWrite.Close()

	// Attach tracepoint to sys_exit_open
	tpExitWrite := utils.AttachTracepoint("sys_enter_exit", objs.user_actionsPrograms.TraceLogout)
	defer tpExitWrite.Close()

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
func readEvents(rd *perf.Reader, acts chan action.Action) {
	for {
		record, err := rd.Read()
		if err != nil {
			dbg.DebugPrintf("ERROR: Reading from ring buffer: %v", err)
			continue
		}

		// Determine the type of event based on the size of the record
		act := action.UnmarshallAction(record.RawSample)
		if act != (action.Action{}) {
			acts <- action.UnmarshallAction(record.RawSample)
		}
	}
}

/*
Initializes the bpf objects, loading them into userspace
returns bpf objects
*/
func initializeBPFObjects() user_actionsObjects {
	objs := user_actionsObjects{}
	dbg.DebugPrintlnExtra("\nLoading eBPF objects...")
	if err := loadUser_actionsObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
		os.Exit(-1)
	}
	dbg.DebugPrintlnExtra("Done!")
	return objs
}

/*
Attempts to create a Reader to extract data from the ring buffer
*/
func createRingBufferReader(objs user_actionsObjects) *perf.Reader {
	dbg.DebugPrintlnExtra("\nCreating reader...")
	rd, err := perf.NewReader(objs.user_actionsMaps.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Opening ring buffer reader: %v", err)
		os.Exit(-4)
	}
	dbg.DebugPrintlnExtra("Done!")
	return rd
}
