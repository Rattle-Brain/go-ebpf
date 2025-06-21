#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Tracepoint for syscalls:sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int example_printk_trace(struct pt_regs *ctx) {
    long bytes = bpf_printk("Hello, eBPF!\n", 0);
    bpf_printk("Bytes written: %ld\n", bytes);
    return 0;
}

// The license is important, don't forget to put it
char _license[] SEC("license") = "GPL";

