package probe

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"go.mod/clsact"
	"golang.org/x/sys/unix"
)

/*
This directive compiles the ebpf code and appends the executable file
into golang code for it to be used.
*/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/code.bpf.c - -O2  -Wall -Werror -Wno-address-of-packed-member

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

func (p *probe) loadObjects() error {
	fmt.Printf("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	fmt.Println("Creating a new probe")
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		fmt.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	// We create a new probe
	prb := probe{
		iface:  iface,
		handle: handle,
	}

	// We try to load the eBPF objects and check for errors
	err = prb.loadObjects()
	if err != nil {
		fmt.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	// We now create the Qdisc and attach it to the probe
	// Then, obviously, we check for errors
	err = prb.createQdisc()
	if err != nil {
		fmt.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	err := prb.createFilters()
	if err != nil {
		fmt.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prb, nil
}
