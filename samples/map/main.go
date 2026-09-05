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

	// Attach the program to the openat syscall tracepoint
	link, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.codePrograms.TraceEnterOpen, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer link.Close()

	// The map itself is only used to illustrate bpf_map_lookup_elem/bpf_map_update_elem
	// from kernel space; we don't need to read it from userspace for this example.
	// You can check the results using `sudo cat /sys/kernel/debug/tracing/trace_pipe`
	// or `sudo cat /sys/kernel/tracing/trace_pipe`, same as the printk/pid_tgid samples.

	// Set up signal handling to clean up on exit (Ctrl+C or SIGTERM)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("Exiting...")
		os.Exit(0)
	}()

	for {
		print("Program is running... Press Ctrl+C to exit.\n")
		time.Sleep(10 * time.Second)
	}
}
