#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Unlike the tracepoint-based samples, a kprobe attaches directly to a real
// kernel function by name instead of a tracepoint. __x64_sys_execve is the
// syscall entry point for execve on x86_64: it always runs on every exec,
// regardless of whether any tracepoint consumer is active elsewhere.
SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
  struct task_struct *task;
  pid_t pid;
  char comm[TASK_COMM_LEN];

  task = (struct task_struct *)bpf_get_current_task();
  pid = BPF_CORE_READ(task, pid);
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_printk("KPROBE execve: [%d] %s", pid, comm);

  return 0;
}
