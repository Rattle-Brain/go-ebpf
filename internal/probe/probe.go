package probe

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"go.mod/clsact"
	"go.mod/dbg"
	"go.mod/file"
	"go.mod/internal/flowtable"
	"go.mod/internal/packet"
	"golang.org/x/sys/unix"
)

/*
This directive compiles the ebpf code and appends the executable file
into golang code for it to be used.
*/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/code.bpf.c - -O2  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

var fileName string
var dataFile *os.File
var existsFile bool = false

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

func (prb *probe) loadObjects() error {
	dbg.DebugPrintln("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	prb.bpfObjects = &objs

	return nil
}

/*
Sets the Ram memory limit.
The minimum is the Cur field, set to twenty MB,
whereas the maximun, corresponding to the Max field
is set to 40MB
*/
func setMEMLimit() error {
	dbg.DebugPrintln("Setting rlimit")

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: twentyMegaBytes,
		Max: fortyMegaBytes,
	})
}

func (prb *probe) createQdisc() error {
	dbg.DebugPrintln("Creating qdisc")

	// We create a new qdisc -> clsact with the parameters we need
	prb.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: prb.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	// Let's try and add the qdisc
	err := prb.handle.QdiscAdd(prb.qdisc)
	if err != nil {
		if err := prb.handle.QdiscReplace(prb.qdisc); err != nil {
			return err
		}
	}

	return nil
}

/*
Now we need to create a fucntion that inserts the filters into the
filter field of the probe we created. For that, we have a function
addFilter that inserts the filter, and another func that creates all
the filters, createFilters.
*/
func (prb *probe) createFilters() error {
	dbg.DebugPrintln("Creating qdisc filters")

	// Ingress and egress filters for IPv4
	addFilter(prb, netlink.FilterAttrs{
		LinkIndex: prb.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilter(prb, netlink.FilterAttrs{
		LinkIndex: prb.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	// Ingress and egress filters for IPv6
	addFilter(prb, netlink.FilterAttrs{
		LinkIndex: prb.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	addFilter(prb, netlink.FilterAttrs{
		LinkIndex: prb.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	// Loop that checks for any errors generated in the previous code
	for _, filter := range prb.filters {
		if err := prb.handle.FilterAdd(filter); err != nil {
			if err := prb.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func addFilter(prb *probe, net netlink.FilterAttrs) {
	prb.filters = append(prb.filters, &netlink.BpfFilter{
		FilterAttrs:  net,
		Fd:           prb.bpfObjects.probePrograms.Interceptor.FD(),
		DirectAction: true,
	})
}

// Function to create a new probe given a network interface
func NewProbe(iface netlink.Link) (*probe, error) {
	dbg.DebugPrintln("Creating a new probe")
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
		fmt.Printf("Failed loading probe objects: %v\n", err)
		return nil, err
	}

	// We now create the Qdisc and attach it to the probe
	// Then, obviously, we check for errors
	err = prb.createQdisc()
	if err != nil {
		fmt.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	// Then we create the filters.
	err = prb.createFilters()
	if err != nil {
		fmt.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prb, nil
}

/*
Lastly, we get to coding te function that runs the probes.
This runs the probe within the context and attaches it to the
interface received through parameter
*/
func (prb *probe) Run(ctx context.Context, iface netlink.Link) error {
	dbg.DebugPrintln("Starting up the probe")
	var err error

	if fileName != "" {
		dataFile, err = file.OpenFile(fileName)
		if err != nil {
			dbg.DebugPrintln("File name did not exist. Creating one...")
			err := file.CreateFile(fileName)
			if err != nil {
				fmt.Println("Couldn't create the file. Exiting...")
				os.Exit(1)
			}
			dataFile, _ = file.OpenFile(fileName)
		}
		existsFile = true
	}

	err = setMEMLimit()
	if err != nil {
		fmt.Printf("Failed setting rlimit: %v", err)
		return err
	}

	// We create a new flowtable that has control over
	// the time the packets are alive and registered.
	// Also, we use a corrutine to avoid pausing the execution of the code.
	ft := flowtable.NewFT()
	go func() {
		for range ft.Ticker.C {
			ft.Flush()
		}
	}()

	// pipe is the eBPF ringbuf map in GO
	pipe := prb.bpfObjects.probeMaps.Pipe

	// So also, we need a reader to get info from the map
	reader, err := ringbuf.NewReader(pipe)

	if err != nil {
		fmt.Println("Failed creating ring buf reader")
		return err
	}

	c := make(chan []byte)

	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				fmt.Printf("Failed reading from ringbuf: %v", err)
				return
			}
			c <- event.RawSample
		}
	}()

	for {
		select {
		case <-ctx.Done():
			ft.Ticker.Stop()
			return prb.Close()

		case pkt := <-c:
			packetAttrs, ok := packet.UnmarshallBins(pkt)
			if !ok {
				fmt.Printf("Could not unmarshall packet: %+v", pkt)
				continue
			}
			ts := packet.CalcLatency(packetAttrs, ft)
			latency := (float64(packetAttrs.TimeStamp) - float64(ts)) / packet.TO_SEC_FROM_NANO
			if existsFile {
				file.AppendToFile(dataFile, packetAttrs, latency)
			}
		}
	}
}

/*
This function handles the process of quitting
the program. Deletes all handlers and removes the
information stored in the clsact, as well as
removing entries from the flow table
*/
func (p *probe) Close() error {
	dbg.DebugPrintln("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		fmt.Println("Failed deleting qdisc")
		return err
	}

	dbg.DebugPrintln("Deleting handle")
	p.handle.Delete()

	dbg.DebugPrintln("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		fmt.Println("Failed closing eBPF object")
		return err
	}

	if existsFile {
		dbg.DebugPrintln("Closing CSV file")
		err := file.CloseFile(dataFile)
		if err != nil {
			fmt.Println("Failed closing the CSV file")
			return err
		}
	}
	return nil
}

func SetFileName(name string) {
	fileName = name
}
