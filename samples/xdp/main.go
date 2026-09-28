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
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

// Must match STAT_AUTHORIZED / STAT_DROPPED in code.bpf.c.
const (
	statAuthorized uint32 = 0
	statDropped    uint32 = 1
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <interface>", os.Args[0])
	}

	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// XDP only ever sees traffic *arriving* at the interface it is attached
	// to. Connections the machine makes to itself never touch a physical
	// interface: they go through the loopback one, lo. The same program is
	// therefore attached to both, so both kinds of traffic are seen.
	for _, name := range []string{"lo", os.Args[1]} {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Fatalf("looking up interface %s: %v", name, err)
		}

		// With no Flags, the kernel uses the driver's native XDP support if
		// it has one, and falls back to generic XDP otherwise (lo has none).
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpHttpGuard,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("attaching XDP to %s: %v", name, err)
		}
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %v", err)
	}
	defer rd.Close()

	// Closing the reader is what unblocks rd.Read() below on Ctrl+C.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		rd.Close()
	}()

	fmt.Printf("Guarding TCP port 80 on lo and %s. Press Ctrl+C to exit.\n", os.Args[1])

	var ev codeEvent
	for {
		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		// saddr was copied as-is from the IP header, so its bytes are already
		// in network order: writing them back out the same way they were
		// read gives the address in its usual a.b.c.d order.
		src := make(net.IP, 4)
		binary.LittleEndian.PutUint32(src, ev.Saddr)

		ifname := fmt.Sprint(ev.Ifindex)
		if iface, err := net.InterfaceByIndex(int(ev.Ifindex)); err == nil {
			ifname = iface.Name
		}

		if uint32(ev.Verdict) == statAuthorized {
			fmt.Printf("[%s] Authorized packet from localhost (%s:%d)\n", ifname, src, ev.Sport)
		} else {
			fmt.Printf("[%s] Unauthorized packet from outside the computer (%s:%d): dropped, %d so far\n",
				ifname, src, ev.Sport, readCounter(&objs, statDropped))
		}
	}

	fmt.Printf("\nExiting... %d packets authorized, %d dropped.\n",
		readCounter(&objs, statAuthorized), readCounter(&objs, statDropped))
}

func readCounter(objs *codeObjects, key uint32) uint64 {
	var value uint64
	if err := objs.Counters.Lookup(key, &value); err != nil {
		log.Printf("reading counter %d: %v", key, err)
	}
	return value
}
