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

	// Unlike link.Kprobe, link.AttachTracing does not take the target name
	// as a parameter: it resolves it from the program's own SEC() string,
	// using the BTF information embedded when it was compiled.
	fentryLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryVfsUnlink,
	})
	if err != nil {
		log.Fatalf("Failed to attach fentry: %v", err)
	}
	defer fentryLink.Close()

	fexitLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FexitVfsUnlink,
	})
	if err != nil {
		log.Fatalf("Failed to attach fexit: %v", err)
	}
	defer fexitLink.Close()

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
