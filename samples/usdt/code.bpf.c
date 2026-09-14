#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// myapp:order_processed is a USDT probe with a single 4-byte signed argument,
// which the compiler encoded as "-4@-4(%rbp)": a value stored 4 bytes below
// the frame pointer at the probe's call site (see main.go for how this
// location is resolved from the target binary's .note.stapsdt ELF note).
// Since the probe fires in userspace, its argument must be read with
// bpf_probe_read_user instead of the kernel-memory helpers used by kprobes.
SEC("uprobe/order_processed")
int usdt_order_processed(struct pt_regs *ctx) {
  long frame_pointer = PT_REGS_FP(ctx);
  int order_id = 0;

  bpf_probe_read_user(&order_id, sizeof(order_id), (void *)(frame_pointer - 4));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("USDT myapp:order_processed [%d] order_id=%d", pid, order_id);

  return 0;
}
