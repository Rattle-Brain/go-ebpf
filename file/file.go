package file

import (
	"encoding/csv"
	"fmt"
	"os"

	"go.mod/internal/packet"
)

func CreateFile(name string) (*os.File, error) {
	header := []string{"Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Latency (ms)"}
	file, err := os.Create(name)
	if err != nil {
		fmt.Printf("Error creating a new file. Permissons?\n")
		return nil, err
	}

	writer := csv.NewWriter(file)
	writer.Write(header)

	return file, nil
}

func OpenFile(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func AppendToFile(file *os.File, pkt packet.Packet, latency float64) error {
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

	data := []string{sip, dip, sport, dport, prot, fmt.Sprintf("%f", latency)}

	err := writer.Write(data)
	if err != nil {
		fmt.Printf("Error writing data to file\n")
		return err
	}
	return nil
}

func CloseFile(file *os.File) error {
	err := file.Close()
	if err != nil {
		return err
	}
	return nil
}
