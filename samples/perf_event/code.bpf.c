#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Unlike every other program in this repository, a perf_event program is not
// attached by name: what it ends up hooked to is decided entirely on the Go
// side, by opening a perf event first and then pointing it at this program.
// The context here is struct bpf_perf_event_data, not pt_regs, though it
// still carries a copy of the registers (ctx->regs) captured at the exact
// instant the sample was taken, which is enough to know where the CPU was.
SEC("perf_event")
int profile_cpu_cycles(struct bpf_perf_event_data *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  char comm[TASK_COMM_LEN];
  __u64 ip = PT_REGS_IP(&ctx->regs);

  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_printk("PERF_EVENT sample: [%d] %s at 0x%llx", pid, comm, ip);

  return 0;
}
