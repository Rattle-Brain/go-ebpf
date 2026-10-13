package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

// cgroup v2 is mounted here on any modern distribution.
const cgroupRoot = "/sys/fs/cgroup"

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <cgroup name>", os.Args[0])
	}
	path := filepath.Join(cgroupRoot, os.Args[1])

	// A cgroup is just a directory in the cgroup filesystem: creating one is a
	// mkdir, and the kernel fills it with its control files.
	created := false
	if err := os.Mkdir(path, 0o755); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		log.Fatalf("creating cgroup %s: %v", path, err)
	}

	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// The program applies to every process in the cgroup (and in any cgroup
	// below it), whatever interface its traffic goes out through.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.SandboxEgress,
	})
	if err != nil {
		log.Fatalf("attaching to cgroup %s: %v", path, err)
	}

	fmt.Printf("Processes in %s can only reach loopback. Press Ctrl+C to exit.\n", path)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	l.Close()
	printBlocked(&objs)

	// rmdir only succeeds once no process is left in the cgroup.
	if created {
		if err := os.Remove(path); err != nil {
			log.Printf("removing cgroup %s: %v", path, err)
		}
	}
}

func printBlocked(objs *codeObjects) {
	type row struct {
		ip      net.IP
		dropped uint64
	}
	var rows []row

	var key uint32
	var dropped uint64
	it := objs.Blocked.Iterate()
	for it.Next(&key, &dropped) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)
		rows = append(rows, row{ip, dropped})
	}
	if err := it.Err(); err != nil {
		log.Printf("reading blocked map: %v", err)
	}

	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].ip, rows[j].ip) < 0 })

	fmt.Printf("\nBlocked destinations:\n")
	fmt.Printf("%-15s %8s\n", "DESTINATION", "DROPPED")
	for _, r := range rows {
		fmt.Printf("%-15s %8d\n", r.ip, r.dropped)
	}
}
