package file

import (
	"encoding/csv"
	"fmt"
	"os"

	"go.mod/internal/packet"
)

/*
This module is an abstraction of a file, adapted to work better
with what we need here.
*/

/*
Creates a new file, and adds a header to knwo what each field is
*/
func CreateFile(name string) error {
	header := []string{"Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Latency (ms)"}
	file, err := os.Create(name)
	if err != nil {
		fmt.Printf("Error creating a new file. Permissons?\n")
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write(header)
	defer writer.Flush()

	return nil
}

/*
Opens an existing file, or returns error if it can't
*/
func OpenFile(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

/*
Appends data to an opened file. The data is received from the pkt parameter,
which contains the unmarshalled information of the intercepted Packet
*/
func AppendToFile(file *os.File, pkt packet.Packet, latency float64) error {

	if latency != 0 {

		writer := csv.NewWriter(file)
		defer writer.Flush()

		sip := pkt.SrcIP.Unmap().String()
		dip := pkt.DstIP.Unmap().String()
		sport := fmt.Sprintf("%d", pkt.SrcPort)
		dport := fmt.Sprintf("%d", pkt.DstPort)

		var prot string
		if pkt.Protocol == packet.UDP {
			prot = "UDP"
		} else {
			prot = "TCP"
		}

		data := []string{sip, dip, sport, dport, prot, fmt.Sprintf("%.3f", latency)}

		err := writer.Write(data)
		if err != nil {
			fmt.Printf("Error writing data to file\n")
			return err
		}

	}
	return nil
}

/*
Closes a file after every byte has ben flushed out of the buffer of
the writer.
*/
func CloseFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	err := file.Close()
	if err != nil {
		return err
	}
	return nil
}
