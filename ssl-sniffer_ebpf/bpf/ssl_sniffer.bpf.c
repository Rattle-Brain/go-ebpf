// SPDX-License-Identifier: GPL-2.0
//
// ssl_sniffer.bpf.c - capture TLS plaintext at the OpenSSL API boundary.
//
// TLS libraries expose functions whose arguments are *plaintext*:
//
//   int SSL_write(SSL *ssl, const void *buf, int num);
//   int SSL_read (SSL *ssl,       void *buf, int num);
//   int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);
//   int SSL_read_ex (SSL *ssl,       void *buf, size_t num, size_t *readbytes);
//
// Whatever an application hands to SSL_write has not been encrypted yet, and
// whatever SSL_read hands back has already been decrypted. Attaching uprobes
// to these functions therefore lets us observe the cleartext stream without
// touching keys, certificates or ciphertext at all.
//
// Every function is instrumented with an entry/return pair:
//
//   uprobe     (entry):  remember the arguments (ssl, buf, out-pointer)
//   uretprobe  (return): look at the return value and, if the call succeeded,
//                        copy the bytes that were actually transferred.
//
// For SSL_read this pairing is mandatory: on entry `buf` is still empty. For
// SSL_write the plaintext is already present on entry, but we still wait for
// the return because a non-blocking socket can make SSL_write fail with
// SSL_ERROR_WANT_WRITE, after which the application retries with the very
// same buffer. Reading on entry would report that data twice (or report data
// that was never sent); reading on return reports exactly what went out.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// 16 KiB is the maximum plaintext size of a single TLS record. Applications
// may pass larger buffers to SSL_write/SSL_read; anything beyond MAX_DATA is
// cut and the event is flagged as truncated.
#define MAX_DATA 16384

// 16 * 1024 (2^14) for kernel alignment . This variable is decoupled from MAX_DATA
// and is actually capped by /proc/sys/kernel/pid_max . Kernel defaults to 32768
#define MAX_ENTRIES 16384

enum ssl_dir {
  DIR_READ = 0,  // data received (after decryption)
  DIR_WRITE = 1, // data sent (before encryption)
};

// One captured chunk of plaintext. The Go side decodes the fixed-size header
// (everything before `data`) by hand, so keep internal/event/event.go in sync
// with this layout.
struct ssl_event {
  __u64 ts_ns;   // bpf_ktime_get_ns() at the time of the return probe
  __u64 ssl_ptr; // address of the SSL object: a stable per-connection id
  __u32 pid;     // thread group id (what userspace calls the PID)
  __u32 tid;     // thread id
  __u32 len;     // number of bytes in data[]
  __u32 orig_len; // number of bytes the SSL call actually transferred
  __u8 dir;      // enum ssl_dir
  __u8 truncated; // orig_len > MAX_DATA
  __u8 _pad[6];
  char comm[16]; // task name
  __u8 data[MAX_DATA];
};

// Arguments saved by an entry probe for the matching return probe.
struct ssl_args {
  __u64 ssl;
  __u64 buf;
  __u64 out_len; // size_t * of the *_ex variants, 0 otherwise
};

// In-flight calls, keyed by pid_tgid. Keying by thread (not process) is what
// makes entry/return pairing correct when many threads use TLS at once: a
// thread can only be inside one SSL_read/SSL_write at a time.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u64);
  __type(value, struct ssl_args);
} active_calls SEC(".maps");

// A struct ssl_event is ~16 KiB, far beyond the 512-byte BPF stack limit, so
// it is assembled in a per-CPU scratch slot instead. Per-CPU means no locking:
// a BPF program cannot be preempted by another one on the same CPU.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct ssl_event);
} scratch SEC(".maps");

// Transport to userspace. bpf_ringbuf_output() copies only header + payload,
// so a 40-byte HTTP request costs 40 bytes of ring space, not 16 KiB.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_ENTRIES);
} events SEC(".maps");

// Events that could not be delivered because the ring buffer was full.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} dropped SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline void save_args(void *ssl, const void *buf,
                                      size_t *out_len) {
  __u64 id = bpf_get_current_pid_tgid();
  struct ssl_args args = {
      .ssl = (__u64)ssl,
      .buf = (__u64)buf,
      .out_len = (__u64)out_len,
  };
  bpf_map_update_elem(&active_calls, &id, &args, BPF_ANY);
}

static __always_inline void emit(struct ssl_args *args, __u64 n, __u8 dir) {
  __u32 zero = 0;
  struct ssl_event *e = bpf_map_lookup_elem(&scratch, &zero);
  if (!e)
    return;

  __u64 id = bpf_get_current_pid_tgid();
  e->ts_ns = bpf_ktime_get_ns();
  e->ssl_ptr = args->ssl;
  e->pid = id >> 32;
  e->tid = (__u32)id;
  e->dir = dir;
  e->orig_len = n;
  e->truncated = n > MAX_DATA;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  // The verifier must be able to prove that `len` never exceeds the size of
  // e->data, otherwise it rejects both the read and the ringbuf output below.
  __u32 len = n > MAX_DATA ? MAX_DATA : n;
  e->len = len;

  // The buffer lives in the traced process' address space, hence _user.
  if (bpf_probe_read_user(e->data, len, (void *)args->buf) != 0)
    return;

  __u64 size = __builtin_offsetof(struct ssl_event, data) + len;
  if (size > sizeof(*e)) // redundant at runtime, keeps the verifier happy
    return;

  if (bpf_ringbuf_output(&events, e, size, 0) != 0) {
    __u64 *cnt = bpf_map_lookup_elem(&dropped, &zero);
    if (cnt)
      (*cnt)++;
  }
}

// Return path of SSL_read / SSL_write: the return value is the byte count,
// <= 0 meaning error or "try again".
static __always_inline int handle_ret(int ret, __u8 dir) {
  __u64 id = bpf_get_current_pid_tgid();
  struct ssl_args *args = bpf_map_lookup_elem(&active_calls, &id);
  if (!args)
    return 0;

  if (ret > 0)
    emit(args, (__u64)ret, dir);

  bpf_map_delete_elem(&active_calls, &id);
  return 0;
}

// Return path of SSL_read_ex / SSL_write_ex: the return value is 1 on
// success, and the byte count was written through the size_t * argument,
// which we now have to read back from user memory.
static __always_inline int handle_ret_ex(int ret, __u8 dir) {
  __u64 id = bpf_get_current_pid_tgid();
  struct ssl_args *args = bpf_map_lookup_elem(&active_calls, &id);
  if (!args)
    return 0;

  size_t n = 0;
  if (ret == 1 && args->out_len &&
      bpf_probe_read_user(&n, sizeof(n), (void *)args->out_len) == 0 && n > 0)
    emit(args, n, dir);

  bpf_map_delete_elem(&active_calls, &id);
  return 0;
}

// ---------------------------------------------------------------------------
// Programs
//
// The SEC() names only describe the program type; the Go loader decides which
// library and symbol each program is attached to. Note that a single entry
// program serves both SSL_read and SSL_write, since their entry handling is
// identical: only the return side needs to know the direction.
// ---------------------------------------------------------------------------

SEC("uprobe")
int BPF_UPROBE(ssl_rw_enter, void *ssl, const void *buf, int num) {
  save_args(ssl, buf, 0);
  return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_rw_ex_enter, void *ssl, const void *buf, size_t num,
               size_t *out_len) {
  save_args(ssl, buf, out_len);
  return 0;
}

// ---------------------------------------------------------------------------
// NSPR (Firefox / NSS)
//
// PR_Read/PR_Write are NSPR's generic I/O calls: Firefox also uses them on
// files and on the internal pipe that wakes its socket thread. Only calls on
// network connections are interesting, so the entry probe walks the layer
// stack down to the bottom descriptor and keeps the call only if that is a
// TCP socket. Everything else is dropped here, before it costs anything.
//
// From prio.h (x86-64):
//
//   struct PRFileDesc {
//     const PRIOMethods *methods;  //  0
//     PRFilePrivate *secret;       //  8
//     PRFileDesc *lower;           // 16  next layer down, NULL at the bottom
//     PRFileDesc *higher;          // 24
//     ...
//   };
//   struct PRIOMethods {
//     PRDescType file_type;        //  0  enum, 4 bytes
//     ...
//   };
//
// NSPR's ABI has been frozen for decades, so these offsets are stable.
// ---------------------------------------------------------------------------

#define PRFD_METHODS_OFF 0
#define PRFD_LOWER_OFF 16
#define PR_DESC_SOCKET_TCP 2
// A TLS socket in Firefox is TCP + SSL + a couple of Necko layers. 8 leaves
// plenty of room while keeping the loop bounded for the verifier.
#define NSPR_MAX_LAYERS 8

static __always_inline int nspr_is_tcp(const void *fd) {
  __u64 cur = (__u64)fd;

#pragma unroll
  for (int i = 0; i < NSPR_MAX_LAYERS; i++) {
    __u64 lower = 0;
    if (bpf_probe_read_user(&lower, sizeof(lower),
                            (void *)(cur + PRFD_LOWER_OFF)) != 0)
      return 0;

    if (!lower) {
      // Bottom layer: its methods table says what kind of descriptor it is.
      __u64 methods = 0;
      __u32 type = 0;
      if (bpf_probe_read_user(&methods, sizeof(methods),
                              (void *)(cur + PRFD_METHODS_OFF)) != 0 ||
          !methods)
        return 0;
      if (bpf_probe_read_user(&type, sizeof(type), (void *)methods) != 0)
        return 0;
      return type == PR_DESC_SOCKET_TCP;
    }
    cur = lower;
  }
  return 0; // deeper than any real stack: not something we understand
}

SEC("uprobe")
int BPF_UPROBE(nspr_rw_enter, void *fd, const void *buf, int num) {
  // Without saved arguments, the return probe ignores the call.
  if (nspr_is_tcp(fd))
    save_args(fd, buf, 0);
  return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_read_exit, int ret) { return handle_ret(ret, DIR_READ); }

SEC("uretprobe")
int BPF_URETPROBE(ssl_write_exit, int ret) {
  return handle_ret(ret, DIR_WRITE);
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_read_ex_exit, int ret) {
  return handle_ret_ex(ret, DIR_READ);
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_write_ex_exit, int ret) {
  return handle_ret_ex(ret, DIR_WRITE);
}
