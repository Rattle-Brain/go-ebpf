/**
vmlinux.h is autogenerated. Run the following comand in your machine if you want
to use it:

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > sra-monitor_ebpf/bpf/vmlinux.h
*/
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/libbpf_common.h>

#include <asm/ptrace.h>
*/

#define LEN_FILENAME 64
#define LEN_COMM 16

#define MAX_ENTRIES 1024

// Macro that allows to obtain the PID
#define GETPID(x) x >> 32

// Stores entering syscall data
struct data_enter {
    u32 pid;
    u32 uid;
    char comm[LEN_COMM];
    char filename[LEN_FILENAME];
    u64 timestamp;
};

// Stores exitting syscall data
struct data_exit {
    int pid;
    u32 uid;
    char comm[LEN_COMM];
    u64 timestamp;
    int ret_value;  // Return value
};

// Perf map to store events (data_enter/data_exit)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, int);
} file_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, int);
} debug_map SEC(".maps");

// Entry arguments. 
// Documentation in /sys/kernel/tracing/events/syscalls/sys_enter_open
struct entry_args_t {
    char _padding1[24];

    const char* filename;
    int flags;
    umode_t mode;
};

// Exit arguments. 
// Documentation in /sys/kernel/tracing/events/syscalls/sys_enter_open
struct exit_args_t {
    char _padding1[16];

    long ret;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_open(struct entry_args_t *ctx) {
    struct data_enter dat = {};
    u32 key = 0;
    int ret = 0;

    //libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Get the filename that was accessed
    ret = bpf_probe_read_user_str(&dat.filename, sizeof(dat.filename), ctx->filename);
    if (ret < 0) {
        bpf_map_update_elem(&debug_map, &key, &ret, BPF_ANY);
        return 0;
    }

    // Output contents to perfmap
    ret = bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));
    if (ret < 0) {
        bpf_map_update_elem(&debug_map, &key, &ret, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_open(struct exit_args_t *ctx){
    struct data_exit dat= {};

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Extract the return value form *ctx
    dat.ret_value = ctx->ret;

    // Output contents to perfmap
    bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));
    
    return 0;
}
/*
SEC("tracepoints/syscalls/sys_enter_read")
int trace_enter_read(struct pt_regs *ctx) {
    struct data_enter dat = {};

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Get the filename that was accessed
    bpf_probe_read_user_str(&dat.filename, sizeof(dat.filename), (void *)PT_REGS_PARM1(ctx));

    // Output contents to perfmap
    bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct pt_regs *ctx){
    struct data_exit dat= {};

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Extract the return value form *ctx
    dat.ret_value = PT_REGS_RC(ctx);

    // Output contents to perfmap
    bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));
    
    return 0;
}


SEC("tracepoints/syscalls/sys_enter_write")
int tracepoint_enter_write(struct pt_regs *ctx) {
    struct data_enter dat = {};

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Get the filename that was accessed
    bpf_probe_read_user_str(&dat.filename, sizeof(dat.filename), (void *)PT_REGS_PARM1(ctx));

    // Output contents to perfmap
    bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct pt_regs *ctx){
    struct data_exit dat= {};

    // Extract PID, UID and timestamp
    dat.pid = GETPID(bpf_get_current_pid_tgid());
    dat.uid = bpf_get_current_uid_gid();
    dat.timestamp = bpf_ktime_get_ns();

    // Get the process that called the sys_open syscall
    bpf_get_current_comm(&dat.comm, sizeof(dat.comm));

    // Extract the return value form *ctx
    dat.ret_value = PT_REGS_RC(ctx);

    // Output contents to perfmap
    bpf_perf_event_output(ctx, &file_event_map, BPF_F_CURRENT_CPU, &dat, sizeof(dat));
    
    return 0;
}
*/

/*
Cool original idea but ingored for the moment.
*****************************************************
SEC("kprobe/sys_rename")
int kprobe_sys_rename(struct pt_regs *ctx) {
    // Extract relevant information and process it
    return 0;
}

SEC("kprobe/sys_unlink")
int kprobe_sys_unlink(struct pt_regs *ctx) {
    // Extract relevant information and process it
    return 0;
}
*/

char _license[] SEC("license") = "GPL";