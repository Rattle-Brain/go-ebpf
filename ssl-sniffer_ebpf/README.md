# SSL Sniffer (eBPF)

`sslsniff` prints the **plaintext** of TLS connections made by processes on the
local machine. It captures data *before* the TLS library encrypts it and
*after* it decrypts it, using eBPF uprobes on the library's read/write API. It
does not touch keys, certificates or ciphertext.

Supported libraries:

| Family | Used by | Hooked at |
|---|---|---|
| **NSS** | Firefox and its forks (LibreWolf, Floorp, Zen, Waterfox, Tor Browser), Thunderbird | NSPR: `PR_Write`, `PR_Read`, `PR_Send`, `PR_Recv` |
| **OpenSSL** | curl, Python, most CLI tools | `SSL_write`, `SSL_read`, `SSL_write_ex`, `SSL_read_ex` |
| **GnuTLS** | wget (some distros), GNOME apps | `gnutls_record_send`, `gnutls_record_recv` |

HTTP/2, which Firefox uses for almost every site, is decoded frame by frame,
with HPACK-compressed headers turned back into text:

```
15:20:41.512903 firefox:Socket Thread[2308/2391] conn=0x7f1c2a3b9e0 -> WRITE 92 bytes HTTP/2
  HEADERS stream=15 END_STREAM
    :method: GET
    :path: /
    :authority: example.com
    :scheme: https
    user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0

15:20:41.640117 firefox:Socket Thread[2308/2391] conn=0x7f1c2a3b9e0 <- READ  1590 bytes HTTP/2
  HEADERS stream=15
    :status: 200
    content-type: text/html
  DATA stream=15 (1256 bytes) END_STREAM
    <!doctype html>
    ...
```

> **Scope.** This tool shows traffic from the local machine only. Root can
> already read the memory of any local process, so the tool gives no new
> capability. It only makes visible what local programs already exchange. Use
> it on machines you own or are authorised to inspect.

## How it works

### Where the plaintext is

```
 application ──► SSL_write(ssl, buf, n) ──► [encrypt] ──► write(fd) ──► kernel ──► network
                        ▲  uprobe/uretprobe: buf is still plaintext here

 application ◄── SSL_read(ssl, buf, n)  ◄── [decrypt] ◄── read(fd)  ◄── kernel ◄── network
                        ▲  uretprobe: buf has just been filled with plaintext
```

Any tool that hooks the kernel (kprobes on `tcp_sendmsg`, XDP, TC, sockmap...)
only sees ciphertext, because encryption happens in userspace. A **uprobe**
puts a breakpoint on an instruction of a userspace ELF file. Here that
instruction is the first one of `SSL_write`/`SSL_read` in `libssl.so`. Every
process that maps the library runs our BPF program when it reaches that
instruction, and the program can read the process' registers and memory.

### Hooked functions

| Function | Signature | Byte count |
|---|---|---|
| `SSL_write` | `int (SSL*, const void *buf, int num)` | return value (> 0) |
| `SSL_read` | `int (SSL*, void *buf, int num)` | return value (> 0) |
| `SSL_write_ex` | `int (SSL*, const void *buf, size_t num, size_t *written)` | `*written` if it returns 1 |
| `SSL_read_ex` | `int (SSL*, void *buf, size_t num, size_t *readbytes)` | `*readbytes` if it returns 1 |
| `gnutls_record_send` | `ssize_t (gnutls_session_t, const void *buf, size_t n)` | return value (> 0) |
| `gnutls_record_recv` | `ssize_t (gnutls_session_t, void *buf, size_t n)` | return value (> 0) |
| `PR_Write` | `PRInt32 (PRFileDesc*, const void *buf, PRInt32 n)` | return value (> 0) |
| `PR_Read` | `PRInt32 (PRFileDesc*, void *buf, PRInt32 n)` | return value (> 0) |
| `PR_Send` | `PRInt32 (PRFileDesc*, const void *buf, PRInt32 n, PRIntn flags, PRIntervalTime t)` | return value (> 0) |
| `PR_Recv` | `PRInt32 (PRFileDesc*, void *buf, PRInt32 n, PRIntn flags, PRIntervalTime t)` | return value (> 0) |

Every row has the same shape: connection handle first, plaintext buffer
second, byte count third. That is why only two kinds of BPF programs exist
(plain and `_ex`), and the Go loader decides which library and symbol each one
is attached to (`internal/libs` lists them per family).

The `_ex` variants exist since OpenSSL 1.1.1. Many programs (Python's `ssl`
module, among others) use them, so the tool hooks them too. They are optional,
and a library that lacks them is still instrumented. The same goes for
`PR_Send`/`PR_Recv`.

### Firefox: why NSPR and not NSS

NSS has no `SSL_write`. Its TLS code is an **NSPR I/O layer** pushed on top of
the TCP socket. Firefox writes to that socket with `PR_Write(fd, buf, n)`,
which calls the SSL layer's `write` method, which encrypts and hands the
record to the socket below via `fd->lower->methods->write(...)`. That inner
call goes through a function pointer, not through the exported `PR_Write`, so
our probe only fires on the outer call, where the data is still plaintext.

```
 Firefox ──► PR_Write(fd) ──► [SSL layer: encrypt] ──► lower->methods->write ──► kernel
                ▲ uprobe: plaintext            (not an exported call: never probed)
```

The `PRFileDesc*` stays the same for the whole connection (NSPR swaps layer
contents in place when it pushes a layer), so it works as a connection id,
just like `SSL*` does for OpenSSL.

The catch: `PR_Read`/`PR_Write` are NSPR's *generic* I/O functions. Firefox
also uses them on files (cache, profile databases) and on an internal pipe
that wakes its socket thread with a single `M` byte. So the NSPR entry probe
(`nspr_rw_enter`) walks the descriptor's layer stack (`fd->lower` until NULL,
at most 8 hops) and reads the bottom layer's `methods->file_type`. Only calls
whose bottom layer is `PR_DESC_SOCKET_TCP` are recorded; files, pipes and UDP
are dropped in the kernel and never reach userspace.

```
 fd (what Firefox passes) ── lower ──► SSL layer ── lower ──► TCP socket
                                                        methods->file_type == PR_DESC_SOCKET_TCP ✓
```

Mozilla's official builds (tarballs, the Mozilla flatpak, Snap) fold NSPR into
`libnss3.so`. `internal/libs` therefore classifies libraries by the symbols
they export, not by their file name, and hooks `PR_Write` wherever it lives.

### Finding the libraries

A uprobe is attached to a **file** (an inode). Every process that maps that
exact file runs the probe; a copy of the same library at a different path is a
different inode and isn't covered. Sandboxed apps bring their own copies, so
the tool looks in three places:

1. `ldconfig -p`: the system libraries.
2. Known install locations: `/usr/lib/*/`, `/opt/*/`, Snap, and flatpak apps
   (system-wide and the invoking user's). These are hooked even if the browser
   isn't running yet.
3. `/proc/*/maps` of running processes. A path there is relative to that
   process's mount namespace: `/usr/lib/libnspr4.so` inside a flatpak is not
   the host's file. Opening it as `/proc/<pid>/root/usr/lib/libnspr4.so`
   reaches the inode that process really uses.

Candidates are deduplicated by inode, because hooking one file through two
paths would report every call twice. `sslsniff -list` prints the result
without needing root.

### Entry/return pairing

Each function gets a **uprobe** (entry) and a **uretprobe** (return):

1. **On entry**, the arguments are only available in registers (`rdi`, `rsi`,
   `rdx`, `rcx` on x86-64). By the time the function returns, those registers
   have been overwritten. So the entry program stores `{ssl, buf, out_len_ptr}`
   in the `active_calls` hash map, keyed by `pid_tgid`. A thread can only be
   inside one call at a time, so this key is unique even in heavily
   multithreaded programs.
2. **On return**, the program looks those arguments up again, checks the return
   value, and copies exactly as many bytes as the call transferred.

For `SSL_read` this is the only option, because on entry the buffer is still
empty. For `SSL_write` the data is already there on entry, but reading it then
would be wrong. On a non-blocking socket, `SSL_write` can fail with
`SSL_ERROR_WANT_WRITE`, and the application must retry with the same buffer.
Capturing on entry would report that data twice. Capturing on return reports
only what was actually written.

The Go loader attaches each **uretprobe before its uprobe**. Done the other
way round, a call already in flight could save its arguments but never have
them consumed. Done this way round, an orphan return finds nothing in the map
and is ignored.

### Getting 16 KiB out of the kernel

A TLS record carries up to 16 KiB of plaintext. That does not fit on the
512-byte BPF stack, so the event is built in a **per-CPU array** slot
(`scratch`). No locking is needed, since BPF programs are not preempted by
other BPF programs on the same CPU. The event is then copied to a **ring
buffer** with `bpf_ringbuf_output(e, header + len)`. Only the bytes actually
used are sent, so a 40-byte request takes 40 bytes of ring space plus the
56-byte header, not 16 KiB.

The verifier has to prove that `len` never exceeds `sizeof(e->data)` before it
allows `bpf_probe_read_user` and `bpf_ringbuf_output`. That is why `emit()`
clamps the length explicitly. Payloads bigger than 16 KiB are truncated, and
the event says so (`captured N`).

When userspace falls behind and the ring is full, the program counts the event
in a per-CPU `dropped` counter. The total is printed on exit.

### Event layout

```c
struct ssl_event {          // offset
  __u64 ts_ns;              //  0  bpf_ktime_get_ns() (CLOCK_MONOTONIC)
  __u64 ssl_ptr;            //  8  SSL* address, used as connection id
  __u32 pid, tid;           // 16
  __u32 len, orig_len;      // 24  captured / transferred bytes
  __u8  dir, truncated;     // 32
  __u8  _pad[6];            // 34
  char  comm[16];           // 40
  __u8  data[16384];        // 56
};
```

Each ring buffer record is variable length, so the Go side decodes the 56-byte
header by hand (`internal/event`) instead of using the type bpf2go generates.
`event_test.go` checks that the Go header and the C layout agree.

The connection handle (`SSL*`, `gnutls_session_t` or `PRFileDesc*`) is the same
for every call on the same TLS session. It works as a cheap **connection
identifier** for matching a request with its response, and the HTTP/2 decoder
keys its per-connection HPACK state on it.

### HTTP/2 decoding

A connection is recognised as HTTP/2 when the client's first bytes are the
24-byte preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (possibly split over several
writes). From then on, each direction is reassembled into frames across event
boundaries, and header blocks are decoded with one HPACK decoder per direction,
since HPACK's dynamic table is per connection and per direction.

HPACK is stateful, so a single missing byte breaks every later header on that
direction. A truncated capture (> 16 KiB) or a decode error marks the direction
as desynced, and the tool says so instead of printing garbage. For the same
reason, a connection that was already open when the sniffer started can't be
decoded: it shows as text with dots.

### Body decompression

A decoded HTTP body is usually still unreadable, because the server compressed
it: Firefox sends `Accept-Encoding: gzip, deflate, br, zstd` and almost every
response comes back `content-encoding: br` or `gzip`. At `-v 2` the tool
reassembles each body (across DATA frames for HTTP/2, de-chunking
`Transfer-Encoding: chunked` for HTTP/1), then decompresses it by the
`content-encoding` it saw in the headers:

```
<- READ 118 bytes HTTP/2
  DATA stream=1 (118 bytes) END_STREAM
  body [br decoded]
    {"event":"telemetry","user_id":"u-8841","app":"firefox",
     "urls_visited":["https://news.example.com","https://mail.example.com"]}
```

- **Codecs:** `gzip`/`x-gzip` and `deflate` (stdlib), `br` (brotli) and `zstd`.
  Chained encodings like `gzip, br` are undone in order.
- **Partial recovery:** a compressed stream cut short (past the 16 KiB capture
  limit, or by a dropped event) is still decoded up to the break — you get the
  plaintext prefix, with a `[br: unexpected EOF]`-style note, instead of
  nothing.
- **Bombs:** decoded output is capped (8 MiB) so a tiny body that expands to
  gigabytes can't exhaust memory.
- **Genuinely binary bodies** (images, fonts, protobuf/gRPC) decode to bytes,
  not text, and show as `[N bytes of binary data]`. Parsing those is a
  possible extension, not done here.

The full decoded text goes to the `-o` JSON log as well (raise `-max` or set
`-max 0` to keep all of it), so a UI gets the real payloads, not dots.

## Project layout

```
ssl-sniffer_ebpf/
├── bpf/
│   ├── ssl_sniffer.bpf.c        # kernel side: probes, maps, event emission
│   └── vmlinux.h
├── cmd/sslsniff.go              # CLI: flags, output loop, signal handling
└── internal/
    ├── probe/                   # bpf2go bindings + attach logic (Target/SymSpec)
    ├── libs/                    # find + classify OpenSSL/GnuTLS/NSS libraries
    └── event/                   # decode records, print text or decoded HTTP/2
```

## Building

Requirements: Go ≥ 1.25, clang, libbpf headers (`bpf/bpf_helpers.h`), and
kernel ≥ 5.8 (ring buffer).

```bash
cd ssl-sniffer_ebpf
go generate ./...                       # compiles bpf/ssl_sniffer.bpf.c via bpf2go
go build -ldflags "-s -w" -o sslsniff ./cmd
```

Alternatively, using [Nix](https://nixos.org/download/) with [Flakes](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html)
provides a reproducible userspace toolchain isolated from your host packages, albeit it still requires a linux host with
kernel >= 5.8 and `sudo` for runtime execution:

```bash
# inside ssl-sniffer_ebpf directory
nix develop
```

This evaluates `flake.nix`, provisions the required C/eBPF/Go build tools in `/nix/store`,
and opens a shell with helper commands (compile, cleanup, sniff*) preloaded in PATH.

## Usage

```bash
./sslsniff -list                         # what would be hooked (no root needed)
sudo ./sslsniff                          # every supported library, every process
sudo ./sslsniff -libs nss -v 0           # Firefox-family browsers, one line per request
sudo ./sslsniff -libs nss -comm librewolf -v 2   # one browser, with bodies
sudo ./sslsniff -comm curl,python3       # only these process or thread names
sudo ./sslsniff -pid 1234                # only one process (filtered in kernel)
sudo ./sslsniff -hex -max 256            # raw: hexdump of every event, first 256 bytes
sudo ./sslsniff -lib /opt/app/libssl.so.1.1   # an extra library, classified by its symbols
sudo ./sslsniff -raw                     # raw: every event as text, no HTTP decoding
```

### Verbosity

`-v` picks how much is shown (default `1`). HTTP is decoded the same way at
every level, only the output changes.

| `-v` | Shows |
|---|---|
| `0` | One line per request and per response, matched by stream / order |
| `1` | + every header of every request and response |
| `2` | + bodies, **decompressed** (gzip/deflate/br/zstd) and de-chunked, cut to `-max` bytes (default 1024, `0` = all) |
| `3` | + HTTP/2 control frames (SETTINGS, PING, WINDOW_UPDATE...) and data that isn't recognised as HTTP |

```
$ sudo ./sslsniff -libs nss -v 0
16:06:17.255 firefox[59082] -> GET https://example.com/
16:06:17.391 firefox[59082] <- 200 GET https://example.com/ (text/html, 1256 bytes)
16:06:17.402 firefox[59082] -> GET https://example.com/favicon.ico
16:06:17.517 firefox[59082] <- 404 GET https://example.com/favicon.ico (text/html)
```

`-raw` and `-hex` ignore `-v`: they print every captured event as it came in,
which is useful for protocols that aren't HTTP.

### Logging to a file (`-o`)

`-o events.jsonl` writes one JSON object per event to a file, as
[JSON Lines](https://jsonlines.org/): a UI or script can tail it live or parse
it afterwards, so you don't scroll the terminal. The **log always holds every
level**, whatever `-v` is set to, so the terminal and the file are independent.
`-quiet` turns the terminal off and keeps only the file.

```bash
sudo ./sslsniff -libs nss -o events.jsonl          # decode on screen + full log
sudo ./sslsniff -libs nss -o events.jsonl -quiet   # log only
sudo ./sslsniff -o events.jsonl -log-data          # also store raw bytes (base64)
```

Each line is one event:

```json
{
  "time": "2026-11-15T16:06:17.255571+01:00",
  "pid": 59082, "tid": 59104,
  "comm": "firefox:Socket Thread",
  "conn": "0x7f6ca498ae50",
  "dir": "recv",                       // "send" | "recv"
  "protocol": "http2",                 // "http2" | "http1" | ""
  "orig_len": 1256,                    // bytes the TLS call transferred
  "captured": 1256,                    // bytes actually in this record (<= orig_len)
  "truncated": false,
  "lines": [                           // the decoded output, one entry per line
    {"level": 0, "text": "200 GET https://example.com/ (text/html, 1256 bytes)"},
    {"level": 1, "text": "  HEADERS stream=1"},
    {"level": 1, "text": "    :status: 200"},
    {"level": 2, "text": "  DATA stream=1 (1256 bytes)"},
    {"level": 2, "text": "    <!doctype html>..."}
  ],
  "data": "PCFkb2N0eXBl..."            // raw plaintext, base64, only with -log-data
}
```

Each `lines` entry is tagged with the lowest `-v` level that shows it
(`0` summary, `1` headers, `2` bodies, `3` everything), so a UI can offer the
same filtering the terminal does. A quick look with `jq`:

```bash
# every request and response summary, as it is written
tail -f events.jsonl | jq -r '.lines[] | select(.level==0) | .text'
```

### Why not pcap / Wireshark?

A pcap stores real packets, but this tool sees plaintext *after* the TLS
library has de-framed it, so a pcap would mean fabricating fake TCP packets,
which is lossy and often won't dissect. If you specifically want Wireshark,
don't decode in this tool at all: capture the ciphertext with `tcpdump` and
have Firefox write an `SSLKEYLOGFILE` (`about:config` already supports it, via
the environment variable), then point Wireshark at both. That decrypts the
real packet stream. The JSON log here is for feeding a UI the stream *as this
tool decoded it*.

`-comm` matches either the process name (`firefox`, `librewolf`) or the
thread name (`Socket Thread`).

### Demo with Firefox

1. In `about:config`, set `network.http.http3.enable` to `false` (see below).
2. Start the sniffer: `sudo ./sslsniff -libs nss -v 0` (or `-v 1` for headers)
3. **Restart Firefox** (or open a site it hasn't connected to recently).
   Firefox keeps connections open for minutes, and HTTP/2 can only be decoded
   from a connection's start.
4. Browse. Requests and responses show up as decoded HTTP/2.

For OpenSSL, in another terminal:

```bash
curl https://example.com                 # HTTP/2, decoded
curl --http1.1 https://example.com       # HTTP/1.1, plain text
```

## What it can't see

The probes only fire for code that calls OpenSSL's exported functions.

| Client | TLS stack | Why it is missed |
|---|---|---|
| Firefox over **HTTP/3** | NSS inside neqo (QUIC) | QUIC runs over UDP with its own packet I/O; the TLS handshake uses NSS but the data never goes through `PR_Write`/`PR_Read`. Many big sites (Google, Cloudflare, YouTube) use HTTP/3, so turn it off for a demo. |
| Go programs | `crypto/tls` | No libssl at all. Also, uretprobes are unsafe on Go code because goroutine stacks move. |
| Chrome / Electron / many Rust apps | BoringSSL / rustls, statically linked | Symbols are stripped or don't exist, so they would need offsets per build |
| Telegram | MTProto | Messages are encrypted by the app itself before any TLS library sees them |
| Java | JSSE | Implemented in the JVM |

An application that links its own copy of a library is found automatically
while it runs (via `/proc/*/maps`), or with `-lib`, as long as the copy still
exports the hooked symbols.

## Possible extensions

- **Remote address per connection:** hook `SSL_set_fd(ssl, fd)` to map
  `ssl_ptr → fd`, then resolve the socket's peer address with a `connect`
  tracepoint keyed by `(pid, fd)`. Many clients (curl, Python) attach the
  socket through `SSL_set_bio` instead, so a full solution must handle both.
- **Go `crypto/tls`:** attach uprobes to every `RET` instruction of
  `crypto/tls.(*Conn).Read` instead of using a uretprobe, as
  [ecapture](https://github.com/gojue/ecapture) does.
- **pcap output:** write synthetic packets so the decrypted stream can be
  opened in Wireshark.

## Prior art

- BCC's [`sslsniff.py`](https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py)
- [ecapture](https://github.com/gojue/ecapture)
- [Pixie](https://github.com/pixie-io/pixie)'s TLS tracing
