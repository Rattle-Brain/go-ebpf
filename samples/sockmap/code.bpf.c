//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define SERVER_PORT 9000

// Identifies a socket by its connection, seen from that socket's side.
// Ports are kept in host byte order.
struct sock_key {
  __u32 sip;
  __u32 dip;
  __u32 sport;
  __u32 dport;
};

// Every established connection to or from SERVER_PORT, both of its ends.
struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, 1024);
  __type(key, struct sock_key);
  __type(value, __u32);
} sock_hash SEC(".maps");

#define STAT_REDIRECTED 0
#define STAT_PASSED 1

// Messages handed straight to the peer socket, and messages that went
// through the network stack as usual because the peer was not in the map.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

SEC("sockops")
int track_sockets(struct bpf_sock_ops *skops) {
  if (skops->family != AF_INET)
    return 1;
  // Both callbacks fire without enabling any flag: ACTIVE for the socket
  // that called connect(), PASSIVE for the one returned by accept().
  if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
      skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
    return 1;

  // remote_port is in network byte order; local_port, in host byte order.
  __u32 lport = skops->local_port;
  __u32 rport = bpf_ntohl(skops->remote_port);
  if (lport != SERVER_PORT && rport != SERVER_PORT)
    return 1;

  struct sock_key key = {
      .sip = skops->local_ip4,
      .dip = skops->remote_ip4,
      .sport = lport,
      .dport = rport,
  };
  bpf_sock_hash_update(skops, &sock_hash, &key, BPF_ANY);
  return 1;
}

SEC("sk_msg")
int redirect_msg(struct sk_msg_md *msg) {
  // The peer socket sees the same connection with both ends swapped.
  struct sock_key peer = {
      .sip = msg->remote_ip4,
      .dip = msg->local_ip4,
      .sport = bpf_ntohl(msg->remote_port),
      .dport = msg->local_port,
  };

  // BPF_F_INGRESS queues the data as received by the peer, instead of
  // sending it out through the peer.
  __u32 idx = STAT_PASSED;
  if (bpf_msg_redirect_hash(msg, &sock_hash, &peer, BPF_F_INGRESS) == SK_PASS)
    idx = STAT_REDIRECTED;

  __u64 *count = bpf_map_lookup_elem(&stats, &idx);
  if (count)
    __sync_fetch_and_add(count, 1);

  // With a redirect in place, SK_PASS applies it; without one, the message
  // goes through the network stack as usual.
  return SK_PASS;
}
