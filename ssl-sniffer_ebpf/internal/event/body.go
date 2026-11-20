package event

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Limits. A compressed body can be a few hundred bytes that expand to
// gigabytes (a "zip bomb"), so the decoded size is always bounded.
const (
	maxBodyBuf = 8 << 20 // most compressed bytes we buffer per message
	maxDecoded = 8 << 20 // most plaintext we keep after decompression
)

// body accumulates one HTTP message body so it can be de-chunked and
// decompressed once complete. The same type serves HTTP/2 (one per stream,
// framed by END_STREAM) and HTTP/1 (one per direction, framed by
// Content-Length or chunked transfer-encoding).
type body struct {
	encoding string // content-encoding, e.g. "br", "gzip"
	ctype    string // content-type, for the summary only
	buf      []byte // raw bytes as received (still chunked / compressed)
	overflow bool   // exceeded maxBodyBuf: can't be decoded in full

	// HTTP/1 framing. HTTP/2 leaves these zero and flushes on END_STREAM.
	chunked   bool
	hasLength bool
	length    int // Content-Length when hasLength
}

// add appends raw body bytes, up to the buffer cap.
func (b *body) add(p []byte) {
	if b.overflow {
		return
	}
	if len(b.buf)+len(p) > maxBodyBuf {
		b.buf = append(b.buf, p[:maxBodyBuf-len(b.buf)]...)
		b.overflow = true
		return
	}
	b.buf = append(b.buf, p...)
}

// complete reports whether an HTTP/1 body has all arrived. HTTP/2 never calls
// this (its bodies end on an explicit flag).
func (b *body) complete() bool {
	switch {
	case b.overflow:
		return true
	case b.chunked:
		// The final chunk is "0\r\n\r\n" (no trailers) or "0\r\n...\r\n\r\n".
		return bytes.Contains(b.buf, []byte("\r\n0\r\n")) || bytes.HasPrefix(b.buf, []byte("0\r\n"))
	case b.hasLength:
		return len(b.buf) >= b.length
	default:
		return false // length unknown: ends at connection close
	}
}

// decoded returns the body as plaintext: de-chunked if needed, then
// decompressed. note describes what happened (for the output), and is empty
// when the body was plain text that needed nothing. A decode error still
// returns whatever was produced before it (a truncated gzip/br/zstd stream
// yields a usable prefix), with the error in note.
func (b *body) decoded() (data []byte, note string) {
	data = b.buf
	var parts []string

	if b.chunked {
		dechunked, ok := dechunk(data)
		data = dechunked
		if !ok {
			parts = append(parts, "chunked: incomplete")
		}
	}

	if enc := normalizeEncoding(b.encoding); enc != "" {
		dec, err := decompress(enc, data)
		data = dec
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", b.encoding, err))
		} else {
			parts = append(parts, b.encoding+" decoded")
		}
	}

	if b.overflow {
		parts = append(parts, "body truncated")
	}
	if len(parts) > 0 {
		note = " [" + strings.Join(parts, "; ") + "]"
	}
	return data, note
}

// normalizeEncoding drops encodings that mean "no compression".
func normalizeEncoding(enc string) string {
	e := strings.ToLower(strings.TrimSpace(enc))
	if e == "identity" {
		return ""
	}
	return e
}

// decompress decodes one or more chained content-encodings (rare, but
// "gzip, br" is legal; they are applied right-to-left when decoding). Output
// is capped at maxDecoded against decompression bombs.
func decompress(encoding string, data []byte) ([]byte, error) {
	encs := strings.Split(encoding, ",")
	// Decode in reverse: the last listed encoding was applied last.
	for _, enc := range slices.Backward(encs) {
		enc := strings.ToLower(strings.TrimSpace(enc))
		out, err := decodeOne(enc, data)
		if err != nil {
			return out, err // out holds the partial result
		}
		data = out
	}
	return data, nil
}

func decodeOne(enc string, data []byte) ([]byte, error) {
	var r io.Reader
	switch enc {
	case "", "identity":
		return data, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "deflate":
		// RFC 7230 says zlib-wrapped, but some servers send raw DEFLATE.
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			defer zr.Close()
			r = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(data))
			defer fr.Close()
			r = fr
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(data))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return data, fmt.Errorf("unknown encoding %q", enc)
	}

	// LimitReader(+1) lets us notice when a body hits the cap.
	out, err := io.ReadAll(io.LimitReader(r, maxDecoded+1))
	if len(out) > maxDecoded {
		out = out[:maxDecoded]
		if err == nil {
			err = fmt.Errorf("output over %d bytes, truncated", maxDecoded)
		}
	}
	return out, err
}

// dechunk decodes HTTP/1 chunked transfer-encoding. ok is false if the data
// ends mid-stream (the decoded prefix is still returned).
func dechunk(data []byte) (out []byte, ok bool) {
	for len(data) > 0 {
		line, rest, found := cutCRLF(data)
		if !found {
			return out, false
		}
		// A chunk size may carry ";ext" parameters after the hex digits.
		hexSize, _, _ := bytes.Cut(line, []byte(";"))
		n, err := strconv.ParseInt(strings.TrimSpace(string(hexSize)), 16, 64)
		if err != nil {
			return out, false
		}
		if n == 0 {
			return out, true // final chunk
		}
		if int64(len(rest)) < n+2 { // +2 for the trailing CRLF
			out = append(out, rest...) // keep the partial chunk we have
			return out, false
		}
		out = append(out, rest[:n]...)
		data = rest[n+2:] // skip chunk data and its CRLF
	}
	return out, false
}

func cutCRLF(data []byte) (line, rest []byte, found bool) {
	before, after, ok := bytes.Cut(data, []byte("\r\n"))
	if !ok {
		return nil, data, false
	}
	return before, after, true
}
