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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h

func main() {
	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the sched_switch tracepoint
	link, err := link.Tracepoint("sched", "sched_switch", objs.codePrograms.HandleSchedSwitch, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer link.Close()

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
		time.Sleep(10 * time.Second) // Sleep to avoid busy waiting
	}
}
