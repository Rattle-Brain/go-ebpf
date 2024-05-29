package sysopenat

import (
	"log"
	"os"

	"example.com/sra-monitor/dbg"
	"example.com/sra-monitor/internal/event"
	"example.com/sra-monitor/utils"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang openat ../../../bpf/openat_monitor.bpf.c -- -I/usr/include/linux/bpf.h

func Run(evts chan event.Event) {
	dbg.DebugPrintlnExtra("Setting memory limit...")
	utils.SetMemLimit()
	dbg.DebugPrintlnExtra("Done!")

	// Create monitor ebpf objects and load them
	objs := initializeBPFObjects()
	defer objs.Close() // Need to be closed after

	// Attach tracepoint to sys_enter_open
	dbg.DebugPrintlnExtra("\nAttaching Syscall Openat tracepoints...")
	tpEnterOpen := utils.AttachTracepoint("sys_enter_openat", objs.openatPrograms.TraceEnterOpen)
	defer tpEnterOpen.Close()

	// Attach tracepoint to sys_exit_open
	tpExitOpen := utils.AttachTracepoint("sys_exit_openat", objs.openatPrograms.TraceExitOpen)
	defer tpExitOpen.Close()
	dbg.DebugPrintlnExtra("Done!")

	// Create a reader able to extract info from the map
	rd := createRingBufferReader(objs)
	defer rd.Close()

	dbg.DebugPrintlnExtra("\neBPF Openat programs attached. Waiting for events...")
	readEvents(rd, evts)
}

/*
Loops indefinetly to read events from the bpf map as they happen.
*/
func readEvents(rd *perf.Reader, evts chan event.Event) {

	for {
		record, err := rd.Read()
		if err != nil {
			dbg.DebugPrintf("Reading from ring buffer: %v", err)
			continue
		}

		// Determine the type of event based on the size of the record
		evt := event.UnmarshallEvent(record.RawSample)
		if evt != (event.Event{}) {
			evts <- event.UnmarshallEvent(record.RawSample)
		}
	}
}

/*
Initializes the bpf objects, loading them into userspace
returns bpf objects
*/
func initializeBPFObjects() openatObjects {
	objs := openatObjects{}
	dbg.DebugPrintlnExtra("\nLoading eBPF objects...")
	if err := loadOpenatObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
		os.Exit(-1)
	}
	dbg.DebugPrintlnExtra("Done!")
	return objs
}

/*
Attempts to create a Reader to extract data from the ring buffer
*/
func createRingBufferReader(objs openatObjects) *perf.Reader {
	dbg.DebugPrintlnExtra("\nCreating reader...")
	rd, err := perf.NewReader(objs.FileEventMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("Opening ring buffer reader: %v", err)
		os.Exit(-4)
	}
	dbg.DebugPrintlnExtra("Done!")
	return rd
}
