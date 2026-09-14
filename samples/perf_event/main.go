package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

func main() {
	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// cilium/ebpf has no equivalent of link.Kprobe/link.AttachTracing for
	// this program type: a perf event has to be opened by hand first, and
	// only then can the program be set on it. -1 as pid together with a
	// real cpu number means "every thread that ever runs on that CPU".
	//
	// PERF_COUNT_HW_CPU_CYCLES is read straight from the CPU's own
	// performance-monitoring hardware, not from anything the kernel
	// itself tracks: no kprobe, tracepoint or fentry could ever trigger
	// on it. A fixed Sample period (instead of PerfBitFreq) means the
	// program fires once every that many cycles, regardless of how long
	// that takes in wall-clock time.
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_CPU_CYCLES,
		Bits:   unix.PerfBitDisabled,
		Sample: 10_000_000, // once every 10 million CPU cycles
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, 0)
	if err != nil {
		log.Fatalf("opening perf event: %v", err)
	}
	defer unix.Close(fd)

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, objs.ProfileCpuCycles.FD()); err != nil {
		log.Fatalf("attaching bpf program to perf event: %v", err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		log.Fatalf("enabling perf event: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Exiting...")
		os.Exit(0)
	}()

	for {
		print("Program is running... Press Ctrl+C to exit.\n")
		time.Sleep(10 * time.Second) // Sleep to avoid busy waiting
	}
}
