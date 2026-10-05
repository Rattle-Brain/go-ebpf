//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Plain #defines from linux/if_ether.h and linux/pkt_cls.h, which vmlinux.h
// (types only) does not carry. tcx accepts the classic TC_ACT_* codes, since
// its own TCX_PASS / TCX_DROP share their values.
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct stats {
  __u64 packets; // packets let through towards this destination
  __u64 bytes;   // bytes let through, Ethernet header included
  __u64 dropped; // packets dropped because the destination is blocked
};

// Destinations the program must block, filled in from user space. Only the
// presence of a key matters: the value is never read.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u32); // destination IPv4 address, in network byte order
  __type(value, __u8);
} blocked SEC(".maps");

// Outgoing traffic per destination.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32); // destination IPv4 address, in network byte order
  __type(value, struct stats);
} traffic SEC(".maps");

SEC("tcx/egress")
int tc_egress_guard(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  __u32 daddr = ip->daddr;
  struct stats *s = bpf_map_lookup_elem(&traffic, &daddr);
  if (!s) {
    struct stats zero = {};
    bpf_map_update_elem(&traffic, &daddr, &zero, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&traffic, &daddr);
    if (!s)
      return TC_ACT_OK;
  }

  if (bpf_map_lookup_elem(&blocked, &daddr)) {
    __sync_fetch_and_add(&s->dropped, 1);
    return TC_ACT_SHOT;
  }

  __sync_fetch_and_add(&s->packets, 1);
  __sync_fetch_and_add(&s->bytes, skb->len);
  return TC_ACT_OK;
}
