#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sched_switch")
int kprobe_sched_switch(struct pt_regs *ctx) {
  struct task_struct *prev_task;
  struct task_struct *next_task;
  pid_t prev_pid, next_pid;

  // Get the previous and next tasks from the current context
  prev_task = (struct task_struct *)bpf_get_current_task();

  // Read the command names and PIDs
  char prev_comm[TASK_COMM_LEN];
  char next_comm[TASK_COMM_LEN];
  // bpf_probe_read_kernel_str(prev_comm, TASK_COMM_LEN, &prev_task->comm);
  bpf_get_current_comm(&prev_comm, sizeof(prev_comm));

  prev_task = (void*)bpf_get_current_task();
  prev_pid = BPF_CORE_READ(prev_task, pid);
  // bpf_probe_read_kernel(prev_task, sizeof(pid_t), &prev_task->pid);

  // Print the context switch information
  // bpf_trace_printk("CTX_SWITCH: [%d] %s -> [%d] %s\n",
  //                 0, prev_comm);
  
  bpf_printk("CTX HAS SWAPPED: [%d] %s", prev_pid, prev_comm);
  
  return 0;
}
