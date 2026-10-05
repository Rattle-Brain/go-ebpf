package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type stats -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <interface> <blocked IPv4>...", os.Args[0])
	}

	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// The program only knows which destinations to block through this map,
	// so the rule can change without reloading or even touching the program.
	for _, arg := range os.Args[2:] {
		ip := net.ParseIP(arg).To4()
		if ip == nil {
			log.Fatalf("not an IPv4 address: %s", arg)
		}
		if err := objs.Blocked.Put(ipToKey(ip), uint8(1)); err != nil {
			log.Fatalf("blocking %s: %v", ip, err)
		}
	}

	iface, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		log.Fatalf("looking up interface %s: %v", os.Args[1], err)
	}

	// tcx (kernel 6.6+) needs no clsact qdisc: the program is attached
	// through a BPF link, and detached as soon as the link is closed.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgressGuard,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("attaching TC program to %s: %v", iface.Name, err)
	}
	defer l.Close()

	fmt.Printf("Blocking outgoing traffic to %v on %s. Press Ctrl+C to exit.\n", os.Args[2:], iface.Name)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	printTraffic(&objs)
}

// ipToKey turns an IPv4 address into the map key the program builds from the
// IP header: the same four bytes, in network order, read as a u32.
func ipToKey(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip)
}

func printTraffic(objs *codeObjects) {
	type row struct {
		ip    net.IP
		stats codeStats
	}
	var rows []row

	var key uint32
	var value codeStats
	it := objs.Traffic.Iterate()
	for it.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)
		rows = append(rows, row{ip, value})
	}
	if err := it.Err(); err != nil {
		log.Printf("reading traffic map: %v", err)
	}

	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].ip, rows[j].ip) < 0 })

	fmt.Printf("\nOutgoing traffic per destination:\n")
	fmt.Printf("%-15s %8s %8s %8s\n", "DESTINATION", "PACKETS", "BYTES", "DROPPED")
	for _, r := range rows {
		fmt.Printf("%-15s %8d %8d %8d\n", r.ip, r.stats.Packets, r.stats.Bytes, r.stats.Dropped)
	}
}
