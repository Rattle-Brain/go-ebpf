package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"example.com/execvebpf/socket"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang execve ../bpf/execve.bpf.c -- -I/usr/include/linux/bpf.h

type exec_data_t struct {
	Pid    uint32
	F_name [32]byte
	Comm   [32]byte
}

func setLimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("Failed to set memory limit")
	}
}

func main() {
	setLimit()

	var srv_addr string
	var srv_port int
	var conn *net.UDPConn

	// Flags for the program
	flag.StringVar(&srv_addr, "a", "127.0.0.1", "Remote IP address to send data to")
	flag.IntVar(&srv_port, "p", 3040, "Remote port")
	flag.Parse()

	// let's create a connection to a socket UDP (3040 by default)
	conn, err := socket.CreateUDPSocket(srv_addr, srv_port)

	if err != nil {
		fmt.Printf("Error while creating socket UDP")
		os.Exit(-4)
	}

	// Lastly we close the connection, leaving socket available again
	defer conn.Close()

	// We create the eBPF object set
	objs := execveObjects{}

	// Then we load the info rom kspace to uspace
	loadExecveObjects(&objs, nil)

	// Now we attach the program to a kernel event. In this case a tracepoint
	link.Tracepoint("syscalls", "sys_enter_execve", objs.execvePrograms.HandleEnterExecv, nil)

	// Create a reader able to extract info from the map
	reader, err := perf.NewReader(objs.ExecEventMap, os.Getpagesize())

	if err != nil {
		log.Fatalf("Reader error. Quitting...\n")
		os.Exit(-1)
	}

	for {
		event, err := reader.Read()
		if err != nil {
			log.Fatalf("Event reading error. Quitting...\n")
			os.Exit(-2)
		}

		if event.LostSamples != 0 {
			log.Printf("Event ring buffer is full. Dropped events: %d\n", event.LostSamples)
			continue
		}

		byte_array := bytes.NewBuffer((event.RawSample))

		var data exec_data_t

		err = binary.Read(byte_array, binary.LittleEndian, &data)
		if err != nil {
			log.Printf("Error while parsing event: %s\n", err)
			continue
		}
		msg := fmt.Sprintf("CPU %02d %s ran: %d %s\n", event.CPU, data.Comm, data.Pid, data.F_name)

		fmt.Printf("%s", msg)

		dataSend := fmt.Sprintf("%02d %s %d %s\n", event.CPU, data.Comm, data.Pid, data.F_name)

		socket.SendDataUDP(conn, dataSend)
	}

}
