//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// ETH_P_IP lives in linux/if_ether.h as a plain #define, so vmlinux.h (which
// only carries types) does not have it.
#define ETH_P_IP 0x0800
#define HTTP_PORT 80

// Indices into the counters map, and the verdict reported to user space.
#define STAT_AUTHORIZED 0
#define STAT_DROPPED 1

struct event {
  __u32 saddr;   // source IPv4 address, in network byte order
  __u32 ifindex; // interface the packet arrived on
  __u16 sport;   // source TCP port, already in host byte order
  __u8 verdict;  // STAT_AUTHORIZED or STAT_DROPPED
};

// Only sizeof(struct event) is used below, which leaves no trace of the type
// in the object file. This unused pointer keeps it there, so that bpf2go
// (-type event) can generate the matching Go struct.
const struct event *unused_event __attribute__((unused));

// One record per packet sent to port 80, read by the Go side to print a log
// line. Nothing here is printed from the kernel: bpf_printk would work, but
// it writes to a single, global debug buffer shared by every program.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Running totals, kept in the kernel even if the ring buffer ever fills up
// and some events never reach user space.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} counters SEC(".maps");

static __always_inline void report(struct xdp_md *ctx, struct iphdr *ip,
                                   struct tcphdr *tcp, __u32 verdict) {
  __u64 *count = bpf_map_lookup_elem(&counters, &verdict);
  if (count)
    __sync_fetch_and_add(count, 1);

  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return;

  e->saddr = ip->saddr;
  e->ifindex = ctx->ingress_ifindex;
  e->sport = bpf_ntohs(tcp->source);
  e->verdict = verdict;
  bpf_ringbuf_submit(e, 0);
}

// Drops every IPv4 TCP packet addressed to port 80 unless it comes from the
// loopback range (127.0.0.0/8). Anything else (non-IPv4, non-TCP, other
// ports) is passed through untouched.
SEC("xdp")
int xdp_http_guard(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Every header is bounds-checked against data_end before being read:
  // without these checks the verifier refuses to load the program.
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  // The IPv4 header length is variable (ihl counts 32-bit words), so the TCP
  // header does not necessarily start right after struct iphdr.
  struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;
  if (tcp->dest != bpf_htons(HTTP_PORT))
    return XDP_PASS;

  if ((bpf_ntohl(ip->saddr) >> 24) == 127) {
    report(ctx, ip, tcp, STAT_AUTHORIZED);
    return XDP_PASS;
  }

  report(ctx, ip, tcp, STAT_DROPPED);
  return XDP_DROP;
}
