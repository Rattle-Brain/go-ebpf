package utils

import (
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

/*
Attaches a tracepoint given the name of the syscall and the
ebpf program
*/
func AttachTracepoint(syscall_name string, prog *ebpf.Program) link.Link {
	tracepoint, err := link.Tracepoint("syscalls", syscall_name, prog, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint sys_enter_open: %v", err)
		os.Exit(-2)
	}
	return tracepoint
}

func SetMemLimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("Failed to set memory limit")
		os.Exit(-5)
	}
}
