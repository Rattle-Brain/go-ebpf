#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("tc")
int interceptor(struct __sk_buff* skb) {
    
}

char _license[] SEC("license") = "GPL";