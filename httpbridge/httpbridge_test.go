package httpbridge

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/smhanov/merkle"
)

// memSink is an in-memory Sink for tests.
type memSink struct{ data []byte }

func (s *memSink) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(s.data)) {
		return 0, io.ErrShortWrite
	}
	return copy(s.data[off:], p), nil
}

func (s *memSink) Truncate(size int64) error {
	if size < 0 {
		return io.ErrUnexpectedEOF
	}
	if size > int64(len(s.data)) {
		b := make([]byte, size)
		copy(b, s.data)
		s.data = b
	} else {
		s.data = s.data[:size]
	}
	return nil
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestPull(t *testing.T) {
	const size = 3 * 64 * 1024
	old := pattern(size)
	nw := append([]byte(nil), old...)
	for i := 64 * 1024; i < 2*64*1024; i++ { // flip the middle chunk
		nw[i] ^= 0x5A
	}
	srv, err := merkle.NewIndex(bytes.NewReader(nw), size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	ts := httptest.NewServer(NewHandler(srv))
	t.Cleanup(ts.Close)

	// From scratch: an absent file becomes the full new file.
	fresh := &memSink{}
	got, err := Pull(ts.URL, fresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh.data, nw) {
		t.Fatal("from-scratch content mismatch")
	}
	if got.Root() != srv.Root() {
		t.Fatal("from-scratch root mismatch")
	}

	// No-op: a client already up to date exchanges a handshake only.
	same, err := merkle.NewIndex(bytes.NewReader(nw), size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { same.Close() })
	untouched := &memSink{data: append([]byte(nil), nw...)}
	got, err = Pull(ts.URL, untouched, same)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(untouched.data, nw) {
		t.Fatal("no-op must leave the file untouched")
	}
	if got.Root() != srv.Root() {
		t.Fatal("no-op root mismatch")
	}

	// Delta: a client holding the old content receives only the changed
	// chunk and ends up byte-identical to the server.
	prior, err := merkle.NewIndex(bytes.NewReader(old), size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { prior.Close() })
	oldCopy := &memSink{data: append([]byte(nil), old...)}
	got, err = Pull(ts.URL, oldCopy, prior)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldCopy.data, nw) {
		t.Fatal("delta content mismatch")
	}
	if got.Root() != srv.Root() {
		t.Fatal("delta root mismatch")
	}
}
