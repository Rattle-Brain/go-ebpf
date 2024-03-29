package packet

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"reflect"

	"github.com/fatih/color"
	"go.mod/internal/flowtable"
)

/**
Well, we created a struct in C with the information the
network packet should have. The problem is we cannot access
that info straight from the kernel space, so we have to
take it from the kernel maps, unmarshall it and then we can
do things.

As you can see, the packet struct in here is identical as the one
in the bpf directory.

This is the main part of the program. The rest of the files are
"just" to support and help this program run fine.

To do this, unmarshall the information, we'll need to work with offsets
and sizes, since the packet is stored in the map as a bye mesh.

The cheatsheet for the offsets of the packet struct used is as follows:

src_ip:     size = 16,   offset = 0
dst_ip:     size = 16,   offset = 16
src_port:   size = 2,    offset = 32
dst_port:   size = 2,    offset = 34
protocol:   size = 1,    offset = 36
ttl:        size = 1,    offset = 37
syn:        size = 1,    offset = 38
ack:        size = 1,    offset = 39
ts:         size = 8,    offset = 40
*/

// Same attrs as the packet_t struct in code.bpf.c
type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TTL       uint8
	Syn       bool
	Ack       bool
	TimeStamp uint64
}

const UDP = 17
const TCP = 6
const TO_SEC_FROM_NANO = 1_000_000

func UnmarshallBins(marshd []byte) (Packet, bool) {
	// Let's obtain the IP addrs
	sip, okSRC := netip.AddrFromSlice(marshd[0:16])  // Bytes from pos 0-15 -> source IP addr
	dip, okDST := netip.AddrFromSlice(marshd[16:32]) // Bytes from pos 16-31 -> destination IP addr

	// Now we check for errors
	if !okDST || !okSRC {
		return Packet{}, false
	}

	// Now, let's obtain the ports
	// Since they come from the network, the endianity is set to Big Endian.
	sport := binary.BigEndian.Uint16(marshd[32:34])
	dport := binary.BigEndian.Uint16(marshd[34:36])

	// Let's obtain the protocol
	prot := marshd[36] // Note that we don't use endianity transformes, since it's only 1 byte

	// Now the TTL of the packet, as well as syn and ack flags
	ttl_flag := marshd[37]
	syn_flag := marshd[38] == 1 // We have to make this conversion because the
	ack_flag := marshd[39] == 1 // packet is build to take this as bools

	/* Finally, we parse the timestamp.
	The timestamp is obtaind from within the machine, which
	in my case has LittleEndiand architechture, so we need
	to get that information parsed.
	*/
	tstamp := binary.LittleEndian.Uint64(marshd[40:48])

	// Finally, we build the packet to return
	pack := Packet{
		SrcIP:     sip,
		DstIP:     dip,
		SrcPort:   sport,
		DstPort:   dport,
		Protocol:  prot,
		TTL:       ttl_flag,
		Syn:       syn_flag,
		Ack:       ack_flag,
		TimeStamp: tstamp,
	}

	// we build the packet information correctly, so now we return it.
	return pack, true
}

/*
The next two funcs are meant to generate a hash value
to be the key for the flowtable the latency will be stored in.
The first one is the Key Generator itself, where we take the
Source and Destination IP addrs and mesh them together in a single
hash to be used as key for the packet.

The second one is the support function for us to actually generate a hash
of the value we want.
*/

func (pkt *Packet) KeyGen() uint64 {
	if reflect.DeepEqual(pkt, Packet{}) {
		fmt.Printf("Packet to hash is null.\n")
		return 0
	}

	var sip []byte
	var dip []byte

	sip = pkt.SrcIP.AsSlice()
	dip = pkt.DstIP.AsSlice()

	return hash(sip) + hash(dip)

}

func hash(value []byte) uint64 {
	h := fnv.New64()
	h.Write(value)
	return h.Sum64()
}

/*
This fucntion caclulates the latency of every packet that arrives to the
network.
We here used the github.com/fatih/color module in order to make it more
easily noticable whenever the packet is TCP (Yellow) or UDP (Cyan).
You may also notice the value TO_SEC_FROM_NANO which takes as value 1M
because in every second there's a million nanosecs, so thats the factor
we have to use to transform the ns received into seconds
*/
func CalcLatency(pkt Packet, ft *flowtable.FlowTable) float64 {

	var latency float64
	prot := pkt.Protocol
	pktHash := pkt.KeyGen() // This generates the hash, or key, for the map

	ts, ok := ft.Get(pktHash) // And we check if the packet is not already there

	if !ok && prot == TCP {
		ft.Add(pktHash, pkt.TimeStamp)
		return 0
	} else if !ok && prot == UDP {
		ft.Add(pktHash, pkt.TimeStamp)
		return 0
	} else if !ok {
		return 0
	}

	if prot == TCP {
		color.Yellow("TCP | src: %v:%-7v\tdst: %v:%-9v\tTTL: %-4v\tlatency: %.3f ms\n",
			pkt.DstIP.Unmap().String(),
			pkt.DstPort,
			pkt.SrcIP.Unmap().String(),
			pkt.SrcPort,
			pkt.TTL,
			(float64(pkt.TimeStamp)-float64(ts))/TO_SEC_FROM_NANO,
		)
	} else if prot == UDP {
		color.Cyan("UDP | src: %v:%-7v\tdst: %v:%-9v\tTTL: %-4v\tlatency: %.3f ms\n",
			pkt.DstIP.Unmap().String(),
			pkt.DstPort,
			pkt.SrcIP.Unmap().String(),
			pkt.SrcPort,
			pkt.TTL,
			(float64(pkt.TimeStamp)-float64(ts))/TO_SEC_FROM_NANO,
		)
	}

	ft.Remove(pktHash)
	latency = (float64(pkt.TimeStamp) - float64(ts)) / TO_SEC_FROM_NANO
	return latency
}
