package sysopenat

import (
	"fmt"
	"log"
	"os"

	"example.com/sra-monitor/internal/event"
	"example.com/sra-monitor/utils"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang openat ../../../bpf/openat_monitor.bpf.c -- -I/usr/include/linux/bpf.h

func Run() {
	fmt.Println("Setting memory limit...")
	utils.SetMemLimit()
	fmt.Println("Done!")

	// Create monitor ebpf objects and load them
	objs := initializeBPFObjects()
	defer objs.Close() // Need to be closed after

	// Attach tracepoint to sys_enter_open
	fmt.Println("\nAttaching tracepoints...")
	tpEnterOpen := utils.AttachTracepoint("sys_enter_openat", objs.openatPrograms.TraceEnterOpen)
	defer tpEnterOpen.Close()

	// Attach tracepoint to sys_exit_open
	tpExitOpen := utils.AttachTracepoint("sys_exit_openat", objs.openatPrograms.TraceExitOpen)
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

		record_len := len(record.RawSample)

		// Determine the type of event based on the size of the record
		if record_len == 188 {
			event.UnmarshallOpenatEvent(record.RawSample)
		} else {
			log.Printf("unknown event size: %d", record_len)
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