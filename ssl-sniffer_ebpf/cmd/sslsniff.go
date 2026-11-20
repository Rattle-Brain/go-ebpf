// sslsniff prints the plaintext that local processes send and receive through
// TLS libraries (OpenSSL, GnuTLS, and NSS as used by Firefox and its forks),
// captured with eBPF uprobes before encryption / after decryption.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/Rattle-Brain/go-ebpf/ssl-sniffer_ebpf/internal/event"
	"github.com/Rattle-Brain/go-ebpf/ssl-sniffer_ebpf/internal/libs"
	"github.com/Rattle-Brain/go-ebpf/ssl-sniffer_ebpf/internal/probe"
)

// listFlag collects a repeatable / comma separated string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for s := range strings.SplitSeq(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

func main() {
	var (
		extraLibs listFlag
		kindNames listFlag
		comms     listFlag
		pid       int
		hexDump   bool
		maxBytes  int
		noColor   bool
		noHTTP2   bool
		listOnly  bool
		verbosity int
		logPath   string
		logData   bool
		quiet     bool
	)
	flag.Var(&kindNames, "libs", "library families to hook: openssl, gnutls, nss (comma separated, default all). Firefox-based browsers use nss")
	flag.Var(&extraLibs, "lib", "extra library or binary to hook, classified by its exported symbols (repeatable)")
	flag.IntVar(&pid, "pid", 0, "only trace this process ID (filtered in the kernel)")
	flag.Var(&comms, "comm", "only print events whose process or thread name is one of these (comma separated), e.g. firefox")
	flag.IntVar(&verbosity, "v", event.LevelHeaders, "verbosity: 0 = one line per request/response, 1 = + headers, 2 = + bodies, 3 = everything (control frames, non-HTTP data)")
	flag.BoolVar(&hexDump, "hex", false, "raw mode: hexdump every captured event, no HTTP decoding (ignores -v)")
	flag.IntVar(&maxBytes, "max", 1024, "print at most this many body bytes per event or DATA frame (0 = everything captured)")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	flag.BoolVar(&noHTTP2, "raw", false, "raw mode: print every captured event as text, no HTTP decoding (ignores -v)")
	flag.BoolVar(&listOnly, "list", false, "show which libraries would be hooked, then exit (no root needed)")
	flag.StringVar(&logPath, "o", "", "also write every event to this file as JSON Lines (one object per line, all levels), for a UI to tail or parse")
	flag.BoolVar(&logData, "log-data", false, "include the raw plaintext (base64) in the -o log")
	flag.BoolVar(&quiet, "quiet", false, "don't print to the terminal (use with -o)")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("sslsniff: ")

	if verbosity < event.LevelSummary || verbosity > event.LevelAll {
		log.Fatalf("-v must be between %d and %d", event.LevelSummary, event.LevelAll)
	}

	kinds, err := parseKinds(kindNames)
	if err != nil {
		log.Fatal(err)
	}

	targets := libs.Find(kinds)
	if len(extraLibs) > 0 {
		extra := libs.Classify(extraLibs, libs.AllKinds)
		if len(extra) == 0 {
			log.Fatalf("-lib: none of %s exports a supported TLS function", strings.Join(extraLibs, ", "))
		}
		targets = append(targets, extra...)
	}
	if len(targets) == 0 {
		log.Fatal("no TLS library found; pass one explicitly with -lib")
	}

	if listOnly {
		for _, t := range targets {
			fmt.Printf("%-8s %s\n", t.Lib, t.Path)
		}
		return
	}

	sniffer, attached, failed, err := probe.New(targets, probe.Options{PID: pid})
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "skipped: %v\n", f)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer sniffer.Close()

	for _, a := range attached {
		fmt.Fprintf(os.Stderr, "attached %s %s: %s", a.Target.Lib, a.Target.Path, strings.Join(a.Symbols, ", "))
		if len(a.Skipped) > 0 {
			fmt.Fprintf(os.Stderr, " (not exported: %s)", strings.Join(a.Skipped, ", "))
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "tracing TLS plaintext... Ctrl-C to stop")

	// A JSON log is opened before the capture loop so a UI watching the file
	// sees events from the very first one.
	var sink event.Sink
	if logPath != "" {
		f, err := os.Create(logPath)
		if err != nil {
			log.Fatalf("opening log: %v", err)
		}
		defer f.Close()
		sink = event.NewJSONSink(f)
		fmt.Fprintf(os.Stderr, "logging JSON Lines to %s\n", logPath)
	}
	if quiet && sink == nil {
		log.Fatal("-quiet without -o would discard everything; pick one")
	}

	// Closing the reader is what unblocks Read() below.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		sniffer.Events.Close()
	}()

	out := io.Writer(os.Stdout)
	if quiet {
		out = io.Discard
	}
	printer := &event.Printer{
		Out:      out,
		Level:    verbosity,
		Hex:      hexDump,
		MaxBytes: maxBytes,
		Color:    !noColor && !quiet && isTerminal(os.Stdout),
		HTTP2:    !noHTTP2,
		Sink:     sink,
		LogData:  logData,
	}
	wanted := map[string]bool{}
	for _, c := range comms {
		wanted[c] = true
	}
	procNames := map[uint32]string{}

	for {
		rec, err := sniffer.Events.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		ev, err := event.Decode(rec.RawSample)
		if err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		// The kernel reports the thread name. Browsers do their network I/O on
		// named threads (Firefox: "Socket Thread"), so look up the process
		// name too, once per PID.
		thread := ev.Comm
		proc, ok := procNames[ev.PID]
		if !ok {
			proc = processName(ev.PID)
			procNames[ev.PID] = proc
		}
		if proc != "" && proc != ev.Comm {
			ev.Comm = proc + ":" + ev.Comm
		}

		if len(wanted) > 0 && !wanted[proc] && !wanted[thread] {
			continue
		}
		printer.Print(ev)
	}

	if n, err := sniffer.Dropped(); err == nil && n > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d events dropped (ring buffer full)\n", n)
	}
}

func parseKinds(names []string) ([]libs.Kind, error) {
	if len(names) == 0 {
		return libs.AllKinds, nil
	}
	var kinds []libs.Kind
	for _, n := range names {
		k := libs.Kind(strings.ToLower(n))
		switch k {
		case libs.OpenSSL, libs.GnuTLS, libs.NSS:
			kinds = append(kinds, k)
		default:
			return nil, fmt.Errorf("-libs: unknown family %q (want openssl, gnutls or nss)", n)
		}
	}
	return kinds, nil
}

// processName reads the main thread's name, which is the process name. It
// returns "" if the process is already gone.
func processName(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
