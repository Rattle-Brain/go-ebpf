package event

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"

	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func gzipOf(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func zlibOf(s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func brotliOf(s string) []byte {
	var b bytes.Buffer
	w := brotli.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func zstdOf(s string) []byte {
	var b bytes.Buffer
	w, _ := zstd.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

const payload = `{"user":"alice","token":"secret-123","items":[1,2,3],"note":"the interesting part"}`

func TestDecompressRoundTrip(t *testing.T) {
	cases := []struct {
		enc  string
		data []byte
	}{
		{"gzip", gzipOf(payload)},
		{"deflate", zlibOf(payload)},
		{"br", brotliOf(payload)},
		{"zstd", zstdOf(payload)},
		{"identity", []byte(payload)},
		{"", []byte(payload)},
	}
	for _, c := range cases {
		t.Run(c.enc, func(t *testing.T) {
			got, err := decompress(normalizeEncoding(c.enc), c.data)
			if err != nil {
				t.Fatalf("decompress(%s): %v", c.enc, err)
			}
			if string(got) != payload {
				t.Errorf("decompress(%s) = %q", c.enc, got)
			}
		})
	}
}

// A body cut off mid-stream (our 16 KiB cap, or a dropped event) must still
// yield the plaintext decoded before the cut, not nothing.
func TestDecompressTruncatedYieldsPrefix(t *testing.T) {
	long := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 500)
	full := gzipOf(long)
	cut := full[:len(full)-20] // drop the tail

	got, err := decompress("gzip", cut)
	if err == nil {
		t.Error("expected an error on a truncated stream")
	}
	if len(got) == 0 || !strings.HasPrefix(long, string(got)) {
		t.Errorf("partial output is not a prefix of the original (got %d bytes)", len(got))
	}
}

func TestDecompressChained(t *testing.T) {
	// "gzip, br": gzip applied first, then brotli. Decoded br-then-gzip.
	var b bytes.Buffer
	bw := brotli.NewWriter(&b)
	bw.Write(gzipOf(payload))
	bw.Close()

	got, err := decompress("gzip, br", b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Errorf("chained decode = %q", got)
	}
}

func TestDechunk(t *testing.T) {
	// 0x18 = 24 bytes of JSON, then a 5-byte chunk " tail", then the terminator.
	chunked := "18\r\n{\"hello\":\"world\",\"n\":42}\r\n5\r\n tail\r\n0\r\n\r\n"
	got, ok := dechunk([]byte(chunked))
	if !ok {
		t.Error("ok = false for a complete chunked body")
	}
	if string(got) != `{"hello":"world","n":42} tail` {
		t.Errorf("dechunk = %q", got)
	}
}

func TestDechunkIncomplete(t *testing.T) {
	// Second chunk's data hasn't fully arrived; we keep what did.
	got, ok := dechunk([]byte("5\r\nhello\r\n5\r\nwor"))
	if ok {
		t.Error("ok = true for an incomplete chunked body")
	}
	if !strings.HasPrefix(string(got), "hello") {
		t.Errorf("partial dechunk = %q, want at least the first chunk", got)
	}
}

func TestDechunkMissingEndOfFile(t *testing.T) {
	// 0x18 = 24 bytes of JSON, then a 5-byte chunk " tail", then the terminator.
	chunked := "18\r\n{\"hello\":\"world\",\"n\":42}\r\n5\r\n tail\r\n0"
	got, ok := dechunk([]byte(chunked))
	if ok {
		t.Error("ok = true when cutCRLF should have return not found")
	}
	if string(got) != `{"hello":"world","n":42} tail` {
		t.Errorf("dechunk = %q", got)
	}
}

// End to end: a brotli-compressed HTTP/2 response body is revealed as text.
func TestHTTP2CompressedBody(t *testing.T) {
	p, out := newPrinter(LevelBodies)
	feed(p, 1, Write, []byte(http2Preface), 100)

	compressed := brotliOf(payload)
	resp := respHeaders(t, [][2]string{
		{":status", "200"},
		{"content-type", "application/json"},
		{"content-encoding", "br"},
	})
	resp = append(resp, frame(frameData, flagEndStream, 1, compressed)...)
	// Split into 9-byte events: the compressed body spans several DATA frames.
	feed(p, 1, Read, resp, 9)

	got := out.String()
	if !strings.Contains(got, `"token":"secret-123"`) || !strings.Contains(got, "the interesting part") {
		t.Errorf("compressed body was not decoded\n--- got ---\n%s", got)
	}
	if !strings.Contains(got, "br decoded") {
		t.Errorf("missing decode note\n%s", got)
	}
}

func TestHTTP1ChunkedGzipBody(t *testing.T) {
	p, out := newPrinter(LevelBodies)
	feed(p, 2, Write, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 1024)

	gz := gzipOf(payload)
	var chunked bytes.Buffer
	// Two chunks, to exercise reassembly, then the terminator.
	half := len(gz) / 2
	writeChunk(&chunked, gz[:half])
	writeChunk(&chunked, gz[half:])
	chunked.WriteString("0\r\n\r\n")

	// Real HTTP/1 response headers arrive in one TLS record; only the body is
	// split across reads. Feed the header block whole, then the body in pieces.
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
	feed(p, 2, Read, []byte(resp), 4096)
	feed(p, 2, Read, chunked.Bytes(), 13)

	got := out.String()
	if !strings.Contains(got, "the interesting part") {
		t.Errorf("chunked+gzip body not decoded\n--- got ---\n%s", got)
	}
}

func writeChunk(b *bytes.Buffer, data []byte) {
	b.WriteString(strings.ToLower(itohex(len(data))))
	b.WriteString("\r\n")
	b.Write(data)
	b.WriteString("\r\n")
}

func itohex(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{digits[n&0xf]}, buf...)
		n >>= 4
	}
	return string(buf)
}

// respHeaders builds preface-less server frames: a SETTINGS frame and a
// HEADERS frame for stream 1 with the given fields (no END_STREAM).
func respHeaders(t *testing.T, fields [][2]string) []byte {
	t.Helper()
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range fields {
		if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	out.Write(frame(frameSettings, 0, 0, nil))
	out.Write(frame(frameHeaders, flagEndHeaders, 1, hb.Bytes()))
	return out.Bytes()
}
