#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_t {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ttl;
    bool syn;
    bool ack;
    uint64_t ts;
};


struct {
    __uint(map_buffer, BPF_MAP_TYPE_RINGBUF);
    __uint(size, 512 * 1024); /* 512 KB */
} pipe SEC(".maps");


SEC("tc")
int interceptor(struct __sk_buff* skb) {

    /*
        If skb is non-linear the function bpf_skb_pull_data
        pulls the data from the skb struct to a linear region of
        memory, if I get it correctly.

        If it returns a negative number means something failed, so
        we skip the rest of the program and return

        I still have to understand what that parameter 0 is...
    */
    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    /*
        Now we check if the packet is broadcast/multicast. If it is, 
        we drop it, does not interest us, since we want specifically 
        directed packets.
    */
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        return TC_ACT_OK;
    }

    /*
        Now we want to know where the packet data has its start
        and end in memory. We create a void pointer since it's not 
        a specifically typed field. We just want the addresses
    */
    void* head = (void*)(long)skb->data;
    void* tail = (void*)(long)skb->data_end;

    /*
        With the header and tail memory addresses, we now 
        have tot check if the packet is well formed or not.

        The struct ethhdr is Ethernet Header, which means
        that in the space between head and tail should fit the header
        of an ethernet packet. If it doesn't, then the packet is 
        corrupted, lost, malformed or any other problem.

        Meaning we cannot use it, so we drop it.
    */
    if (head + sizeof(struct ethhdr) > tail) {
        return TC_ACT_OK;
    }


    // Now we define the headers
    struct ethhdr* eth = head;  // We can assign ethernet header since we already have it
    struct iphdr* ipv4;           // For ipv4 packets
    struct ipv6hdr* ipv6;       // For IPv6 packets
    struct tcphdr* tcp;         // For TCP packets
    struct udphdr* udp;         // For UDP packets

    // Now we initialize a packet_t struct, but empty.
    struct packet_t pkt = {0};

    /*
        We also should declare another variable that keeps track of the 
        offset, so we don't overstep any boundries, and keep the memory
        accesses within the allocation for the packet itself.

        Prevent SIGSEGV?
    */
    uint32_t offset = 0;

    /*
        Here we select if the packet is IPv4 or IPv6
    */
    switch (bpf_ntohs(eth->h_proto)) {
        // The packet is IPv4
        case ETH_P_IP:
            // The offset is the size of the ethernet and ip headers
            offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

            // We check if the offset stays in bounds, otherwise we exit
            if (head + offset > tail) {
                return TC_ACT_OK;
            }

            // If everything goes well, we allocate space for the IPv4 header
            ipv4 = head + sizeof(struct ethhdr);

            // We check if the protocol is either TCP or UDP, otherwise, we drop the packet
            if (ipv4->protocol != IPPROTO_TCP && ipv4->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
            }

            /*
                This is a weird thing we have to do in order to embed 
                the IPv4 packet in the struct we created previously.
                
                The thing is that the struct is made to work with IPv6, so 
                we have to do this to adapt the IPv6 to a IPv4. That's why 
                the 0xFFFF is there. To indicate that the packet is 
                an IPv4 embedded within a IPv6.
            */
            pkt.src_ip.in6_u.u6_addr32[3] = ipv4->saddr;
            pkt.dst_ip.in6_u.u6_addr32[3] = ipv4->daddr;

            pkt.src_ip.in6_u.u6_addr16[5] = 0xffff;
            pkt.dst_ip.in6_u.u6_addr16[5] = 0xffff;

            pkt.protocol = ipv4->protocol;
            pkt.ttl = ipv4->ttl;

            break;

        // We do the same for IPv6, but in this case, we have to do
        // less, since the struct is meant for this kind of packets
        case ETH_P_IPV6:
            offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

            if (head + offset > tail) {
                return TC_ACT_OK;
            }

            ipv6 = head + sizeof(struct ethhdr);

            if (ipv6->nexthdr != IPPROTO_TCP && ipv6->nexthdr != IPPROTO_UDP) {
                return TC_ACT_OK;
            }

            pkt.src_ip = ipv6->saddr;
            pkt.dst_ip = ipv6->daddr;

            pkt.protocol = ipv6->nexthdr;
            pkt.ttl = ipv6->hop_limit;

            break;

        // If it doesn't match any, drop the packet
        default:
            return TC_ACT_OK;
    }


    /*
        Now lets go with TCP/UDP dicotomy. The idea is basically the same we used before.
        We check if the bounds are correct in order to ensure that we are indeed 
        working with either TCP or UDP. If the protocol differs, drop the packet.
    */
    if (head + offset + sizeof(struct tcphdr) > tail) 
        return TC_ACT_OK;

    if(head + offset + sizeof(struct udphdr) > tail)
        return TC_ACT_OK;

    switch (pkt.protocol) {
        /*
            If the packet is a TCP, we build the rest of the
            struct packet_t with the fields in the header.
        */
        case IPPROTO_TCP:
            tcp = head + offset;
            // If the packet is syn or syn/ack, we get also those flags and the ports.
            if (tcp->syn) {
                pkt.src_port = tcp->source;
                pkt.dst_port = tcp->dest;
                pkt.syn = tcp->syn;
                pkt.ack = tcp->ack;
                // bpf_ktime_get_ns is to know latency of the packet
                pkt.ts = bpf_ktime_get_ns();

                // Then, once built, we send the packet to de user space
                if (bpf_ringbuf_output(&pipe, &pkt, sizeof(pkt), 0) < 0) {
                    return TC_ACT_OK;
                }
            } 
            break;

        /*
            Now we check if the packet is UDP instead, and 
            do basically the same as before, with less steps, of course
        */
        case IPPROTO_UDP:
            udp = head + offset;

            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            pkt.ts = bpf_ktime_get_ns();        // For latency, as before
            
            // Send the data to the user space
            if (bpf_ringbuf_output(&pipe, &pkt, sizeof(pkt), 0) < 0) {
                return TC_ACT_OK;
            }
            break;

        default:  // We did not have a TCP or UDP segment
            return TC_ACT_OK;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";