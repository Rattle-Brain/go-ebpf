package socket

import (
	"fmt"
	"net"
)

/*
Creates a connection between two sockets (local and remote)
host string: Remote IP addr
port int: 	 Remote port
*/
func CreateUDPSocket(host string, port int) (*net.UDPConn, error) {
	// IP and port to send the information to
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	// Local UDP socket.
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := net.DialUDP("udp", localAddr, serverAddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

/*
Sends a string of data (message) to a UDP connection
*/
func SendDataUDP(conn *net.UDPConn, message string) error {
	// Plain text to bytes
	data := []byte(message)

	// Send the data.
	_, err := conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}
