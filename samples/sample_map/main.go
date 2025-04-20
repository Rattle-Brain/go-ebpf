//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang code code.bpf.c  -- -I/usr/include/linux/bpf.h

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the execve syscall tracepoint
	link, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.codePrograms.ExamplePrintkTrace, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer link.Close()

	// Usually we would create a perf event reader to read events from the map defined in the BPF program.
	// However, this program just prints to the kernel log, so we don't need to do that.

	// Set up signal handling to clean up on exit (Ctrl+C or SIGTERM)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Exiting...")
		os.Exit(0)
	}()

	for {
		// The program will run indefinitely, printing to the kernel log.
		// You can check the kernel log using `dmesg` or `journalctl -k`.
		// You can also use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see the trace output.
		// The program will print the execve syscall events to the kernel log.
		print("Program is running... Press Ctrl+C to exit.\n")

		// Sleep for a while to avoid busy waiting
		time.Sleep(10 * time.Second)
	}

}
