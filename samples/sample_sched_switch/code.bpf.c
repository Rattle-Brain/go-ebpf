// trace_sched.c
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "GPL";

struct sched_switch_info {
	char __pad0[8];              // Padding to align the structure
	char prev_comm[16];
	pid_t prev_pid;
    char __pad1[12];             // Padding to align the structure
	char next_comm[16];
	pid_t next_pid;
    char __pad2[4];              // Padding to align the structure
    char __empty[0];
};


// Tracepoint program for sched_switch
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_info *ctx) {
    char prev_comm[16];
    char next_comm[16];
    pid_t prev_pid;
    pid_t next_pid;
    
    bpf_probe_read_kernel_str(prev_comm, sizeof(prev_comm), ctx + 8);
    bpf_probe_read_kernel_str(next_comm, sizeof(next_comm), ctx + 40);

    bpf_probe_read_kernel(&prev_pid, sizeof(prev_pid), ctx + 24);
    bpf_probe_read_kernel(&next_pid, sizeof(next_pid), ctx + 56);


    bpf_trace_printk("CTX_SWITCH: [%d] %s -> [%d] %s\n",
                    prev_pid, prev_comm,
                    next_pid, next_comm);
    return 0;
}
