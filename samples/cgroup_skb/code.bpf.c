//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// cgroup_skb programs have no named verdicts: 1 lets the packet through and
// 0 drops it.
#define CGROUP_DROP 0
#define CGROUP_PASS 1

// Destinations the sandboxed processes tried to reach, and how many of their
// packets were dropped on the way.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // destination IPv4 address, in network byte order
  __type(value, __u64); // dropped packets
} blocked SEC(".maps");

SEC("cgroup_skb/egress")
int sandbox_egress(struct __sk_buff *skb) {
  // Unlike XDP and TC, data starts at the IP header: there is no Ethernet
  // header to skip.
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = data;
  if ((void *)(ip + 1) > data_end)
    return CGROUP_DROP;
  // Deny by default: anything that is not IPv4 (IPv6 included) never leaves.
  if (ip->version != 4)
    return CGROUP_DROP;

  // Loopback (127.0.0.0/8) never leaves the machine, so it is allowed.
  if ((bpf_ntohl(ip->daddr) >> 24) == 127)
    return CGROUP_PASS;

  __u32 daddr = ip->daddr;
  __u64 *count = bpf_map_lookup_elem(&blocked, &daddr);
  if (!count) {
    __u64 zero = 0;
    bpf_map_update_elem(&blocked, &daddr, &zero, BPF_NOEXIST);
    count = bpf_map_lookup_elem(&blocked, &daddr);
    if (!count)
      return CGROUP_DROP;
  }
  __sync_fetch_and_add(count, 1);
  return CGROUP_DROP;
}
