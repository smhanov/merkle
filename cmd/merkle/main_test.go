package main

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestParseSpec(t *testing.T) {
	tests := []struct {
		in     string
		want   spec
		errSub string
	}{
		{in: "file.txt", want: spec{kind: kindLocal, path: "file.txt"}},
		{in: "file:123", want: spec{kind: kindTCP, host: "file", port: 123}},
		{in: "127.0.0.1:9000", want: spec{kind: kindTCP, host: "127.0.0.1", port: 9000}},
		{in: "user@127.0.0.1:9000", want: spec{kind: kindTCP, user: "user", host: "127.0.0.1", port: 9000}},
		{in: "smhanov@megos:/path/to/file", want: spec{kind: kindSSH, user: "smhanov", host: "megos", path: "/path/to/file"}},
		{in: "megos:~/file.txt", want: spec{kind: kindSSH, host: "megos", path: "~/file.txt"}},
		{in: "user@megos", errSub: "missing path"},
		{in: "host:", errSub: "missing path"},
		{in: "h:70000", errSub: "out of range"},
		{in: "h:0", want: spec{kind: kindTCP, host: "h", port: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSpec(tt.in)
			if tt.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errSub) {
					t.Fatalf("parseSpec(%q) = %+v, %v; want error containing %q", tt.in, got, err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSpec(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseSpec(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

// bufferedPipe wraps an io.Pipe so its read side is buffered: a
// goroutine drains the pipe into an internal buffer and blocks
// readers until data arrives or the write end closes. io.Pipe alone
// is unbuffered, which would deadlock the write-first header
// handshake; real transports (socket buffers, ssh pipes) absorb the
// small header writes, and this emulates that.
type bufferedPipe struct {
	w    *io.PipeWriter
	mu   sync.Mutex
	cv   *sync.Cond
	buf  bytes.Buffer
	done bool
}

func newBufferedPipe() *bufferedPipe {
	r, w := io.Pipe()
	b := &bufferedPipe{w: w}
	b.cv = sync.NewCond(&b.mu)
	go func() {
		p := make([]byte, 4096)
		for {
			n, err := r.Read(p)
			b.mu.Lock()
			if n > 0 {
				b.buf.Write(p[:n])
			}
			if err != nil {
				b.done = true
			}
			b.cv.Broadcast()
			b.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return b
}

func (b *bufferedPipe) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 && !b.done {
		b.cv.Wait()
	}
	if b.buf.Len() == 0 {
		return 0, io.EOF
	}
	n, _ := b.buf.Read(p)
	return n, nil
}

func (b *bufferedPipe) Write(p []byte) (int, error) {
	return b.w.Write(p)
}

// pipeConn is an io.ReadWriter over two buffered pipes: reads come
// from the peer's writes, writes go to the peer's reads.
type pipeConn struct {
	rd, wr *bufferedPipe
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.rd.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.wr.Write(p) }

func TestHeaderRoundTrip(t *testing.T) {
	long := strings.Repeat("x", 200)
	cases := []struct {
		name         string
		roleA, roleB byte
		pathA, pathB string
	}{
		{name: "empty paths", roleA: 0, roleB: 1},
		{name: "set paths", roleA: 0, roleB: 1, pathA: "/local/file.txt", pathB: "/remote/file.txt"},
		{name: "long path", roleA: 1, roleB: 0, pathA: long, pathB: long},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aToB := newBufferedPipe()
			bToA := newBufferedPipe()
			a := &pipeConn{rd: bToA, wr: aToB}
			b := &pipeConn{rd: aToB, wr: bToA}

			var ha, hb header
			var ea, eb error
			doneA, doneB := make(chan struct{}), make(chan struct{})
			go func() {
				ha, ea = exchangeHeader(a, tc.roleA, tc.pathA)
				close(doneA)
			}()
			go func() {
				hb, eb = exchangeHeader(b, tc.roleB, tc.pathB)
				close(doneB)
			}()
			<-doneA
			<-doneB
			aToB.w.Close()
			bToA.w.Close()

			if ea != nil {
				t.Fatalf("a: %v", ea)
			}
			if eb != nil {
				t.Fatalf("b: %v", eb)
			}
			wantA := header{role: tc.roleB, path: tc.pathB}
			if ha != wantA {
				t.Fatalf("a got %+v, want %+v", ha, wantA)
			}
			wantB := header{role: tc.roleA, path: tc.pathA}
			if hb != wantB {
				t.Fatalf("b got %+v, want %+v", hb, wantB)
			}
		})
	}
}
