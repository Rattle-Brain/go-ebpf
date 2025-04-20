#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

// Structure to hold execve event data
struct execve_event {
    uint32_t pid;                  // Process ID
    char comm[TASK_COMM_LEN];  // Command name (process name)
};

// Define a perf event map to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} execve_events SEC(".maps");

// Tracepoint for syscalls:sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct execve_event event = {};

    // Get current task (process)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Populate event data with PID and process name
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Send the event to user space through the perf event map
    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// The license is important, don't forget to put it
char _license[] SEC("license") = "GPL";

