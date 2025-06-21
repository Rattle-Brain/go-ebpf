#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sched_switch")
int kprobe_sched_switch(struct pt_regs *ctx) {
    struct task_struct *prev_task;
    struct task_struct *next_task;

    // Get the previous and next tasks from the current context
    prev_task = (struct task_struct *)bpf_get_current_task();
    next_task = (struct task_struct *)bpf_get_current_task();

    // Read the command names and PIDs
    char prev_comm[TASK_COMM_LEN];
    char next_comm[TASK_COMM_LEN];
    bpf_core_read_kernel_str(prev_comm, sizeof(prev_comm), &prev_task->comm);
    bpf_core_read_kernel_str(next_comm, sizeof(next_comm), &next_task->comm);

    pid_t prev_pid = bpf_core_read_kernel(&prev_task->pid);
    pid_t next_pid = bpf_core_read_kernel(&next_task->pid);

    // Print the context switch information
    bpf_trace_printk("CTX_SWITCH: [%d] %s -> [%d] %s\n",
                     prev_pid, prev_comm,
                     next_pid, next_comm);
    
    return 0;
}