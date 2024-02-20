package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
)

/*
Main function, runs the entire program. It's mostly easy to understand,
so won't document much here
*/
func main() {
	var stringInterface string // Defines the interface variable. Will store the interface selected by the user
	fmt.Println("Type the network interface to listen on (e.j eth0):")
	fmt.Scanln(&stringInterface)

	_, ok := netlink.LinkByName(stringInterface) // Attaches the name introduced to an actual understandable var

	// If the function fails, most likely the iface introduced is wrong, so we display
	// all the ifaces available to monitor in the computer
	if ok == nil {
		fmt.Printf("Could not find %s interface\n", stringInterface)
		dispAvailableIfaces()
	}

	// Now we set the program to run in the background
	ctx := context.Background()
	_, ctrl_c := context.WithCancel(ctx)

	// And define a func that handles the CTRL+C shortcut to
	// Terminate the execution
	signalHandler(ctrl_c)
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
