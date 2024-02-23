package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
	"go.mod/dbg"
	"go.mod/internal/probe"
)

var verboseMode bool
var fileName string

/*
Main function, runs the entire program. It's mostly easy to understand,
so won't document much here
*/
func main() {
	// Establish flags for the program to use
	ifaceFlag := flag.String("i", "eth0", "interface to attach the probe to")
	flag.BoolVar(&verboseMode, "v", false, "Enable verbose mode")
	flag.StringVar(&fileName, "f", "", "Create a CSV file to dump the data collected by the interceptor")
	flag.Parse()

	// Send the variables to where they're needed
	dbg.SetVerboseMode(verboseMode)
	probe.SetFileName(fileName)

	iface, ok := netlink.LinkByName(*ifaceFlag) // Attaches the name introduced to an actual understandable var

	// If the function fails, most likely the iface introduced is wrong, so we display
	// all the ifaces available to monitor in the computer
	if ok != nil {
		fmt.Printf("Could not find %s interface\n", *ifaceFlag)
		dispAvailableIfaces()
		os.Exit(1)
	}

	// Now we set the program to run in the background
	ctx := context.Background()
	ctx, ctrl_c := context.WithCancel(ctx)
	prb, err := probe.NewProbe(iface)
	if err != nil {
		fmt.Printf("Error wihle creating the probe\n")
		os.Exit(1)
	}

	// And define a func that handles the CTRL+C shortcut to
	// Terminate the execution
	signalHandler(ctrl_c)

	if err := prb.Run(ctx, iface); err != nil {
		fmt.Printf("Failed running the probe: %v", err)
		os.Exit(1)
	}
}

// Helper function to display the available interfaces in the computer
func dispAvailableIfaces() {
	ifaces, ok := net.Interfaces()

	if ok == nil {
		fmt.Printf("Error getting interfaces. Firmware failure?\n")
	}

	fmt.Printf("Available Interfaces:\n")
	for i, iface := range ifaces {
		fmt.Printf("\t%d. %s\n", i+1, iface.Name)
	}
}

// Helper fucntion that handles the SIGINT interrupt code
func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	/*
		This is  a way to start a corrutine in go, however, I still
		have to understand the syntax used here
	*/
	go func() {
		<-sigChan
		fmt.Println("\nExiting")
		cancel()
	}()
}
