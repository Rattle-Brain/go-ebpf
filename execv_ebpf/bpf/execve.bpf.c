#include <stdbool.h>
#include<stdint.h>
#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#define NAME_LEN 32
#define MAX_ENTRIES 1024

#define FIRST_32_BITS(x) x >> 32
#define LAST_32_BITS(x) x & 0xFFFFFFFF

typedef uint32_t u32;
typedef uint64_t u64;   

// Structure to store the necessary data
struct execv_data_t {
    u32 pid;
    char proc_called[NAME_LEN];
    char calling_proc[NAME_LEN]; 
};

// Struct to create a eBPF Map.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // Type of map
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, MAX_ENTRIES);
} exec_event_map SEC(".maps");

// Entry arguments. 
// Documentation in /sys/kernel/tracing/events/syscalls/sys_enter_execv
struct entry_args_t {
    char _padding1[8];      // Padding
    char _padding2[8];      // More padding

    const char* filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execv")
int handle_enter_execv(struct entry_args_t *args){
    struct execv_data_t data = {};

    // Extraction of pid
    u64 pid;
    pid = bpf_get_current_pid_tgid();
    data.pid = LAST_32_BITS(pid);

    // Extract process called and process calling the execv
    bpf_probe_read_user_str(data.proc_called, NAME_LEN, args->filename);
    bpf_get_current_comm(data.calling_proc, NAME_LEN);

    // Push data into the map.
    bpf_perf_event_output(args, &exec_event_map, BPF_F_CURRENT_CPU,
            &data, sizeof(data));
    
    // Debug message
    bpf_printk("DATA STORED IN MAP CORRECTLY\n");
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";