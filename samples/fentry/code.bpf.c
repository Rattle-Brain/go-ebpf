#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// vfs_unlink(idmap, dir, dentry, delegated_inode) is the VFS-layer function
// that every filesystem's unlink(2)/unlinkat(2) path eventually calls.
// Unlike __x64_sys_execve (used in the kprobe sample), this is the real
// internal function, not the raw syscall trampoline, so its BTF signature
// exposes typed, meaningful arguments straight away.
SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  const unsigned char *fname = BPF_CORE_READ(dentry, d_name.name);

  bpf_printk("FENTRY vfs_unlink: [%d] name=%s", pid, fname);

  return 0;
}

// The fexit counterpart fires after vfs_unlink returns, with an extra
// trailing argument (ret) carrying its return value. Both the original
// arguments and the return value are visible in the very same invocation,
// with no need to correlate entry and exit state by hand.
SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
             struct dentry *dentry, struct inode **delegated_inode, int ret) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  const unsigned char *fname = BPF_CORE_READ(dentry, d_name.name);

  bpf_printk("FEXIT vfs_unlink: [%d] name=%s ret=%d", pid, fname, ret);

  return 0;
}
