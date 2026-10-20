package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

// The root cgroup: the sockops program sees the connections of every process.
const cgroupRoot = "/sys/fs/cgroup"

func main() {
	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// sockops is a cgroup program: it fills the sockhash as connections are
	// established.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.TrackSockets,
	})
	if err != nil {
		log.Fatalf("attaching sockops to %s: %v", cgroupRoot, err)
	}
	defer l.Close()

	// sk_msg is attached to the map itself, not to a hook in the kernel: it
	// runs on every sendmsg() of the sockets the map holds.
	msgOpts := link.RawAttachProgramOptions{
		Target:  objs.SockHash.FD(),
		Program: objs.RedirectMsg,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(msgOpts); err != nil {
		log.Fatalf("attaching sk_msg to the sockhash: %v", err)
	}
	defer link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  msgOpts.Target,
		Program: msgOpts.Program,
		Attach:  msgOpts.Attach,
	})

	fmt.Println("Redirecting local connections on port 9000. Press Ctrl+C to exit.")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	printStats(&objs)
}

func printStats(objs *codeObjects) {
	var redirected, passed uint64
	if err := objs.Stats.Lookup(uint32(0), &redirected); err != nil {
		log.Printf("reading stats: %v", err)
	}
	if err := objs.Stats.Lookup(uint32(1), &passed); err != nil {
		log.Printf("reading stats: %v", err)
	}

	fmt.Printf("\nMessages redirected to the peer socket: %d\n", redirected)
	fmt.Printf("Messages sent through the network stack: %d\n", passed)
}
