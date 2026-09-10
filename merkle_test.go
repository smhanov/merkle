package merkle

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// rw is a bidirectional byte channel built from two one-way pipes,
// standing in for a TCP connection or any other io.ReadWriter.
type rw struct {
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
	close func()
}

func (d *rw) Read(p []byte) (int, error)  { return d.read(p) }
func (d *rw) Write(p []byte) (int, error) { return d.write(p) }

// newPair returns two connected channels: writes on a are read on b
// and vice versa.
func newPair() (*rw, *rw) {
	abR, abW := io.Pipe()
	baR, baW := io.Pipe()
	a := &rw{
		read:  baR.Read,
		write: abW.Write,
		close: func() { abW.Close(); baR.Close() },
	}
	b := &rw{
		read:  abR.Read,
		write: baW.Write,
		close: func() { baW.Close(); abR.Close() },
	}
	return a, b
}

// memSink is a Sink over a byte slice.
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

// corruptLeaf flips one byte of the data of the first leaf frame that
// passes through it, simulating corruption in transit.
type corruptLeaf struct {
	next func([]byte) (int, error)
	buf  []byte
}

func (c *corruptLeaf) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	for len(c.buf) >= 5 {
		n := int(binary.BigEndian.Uint32(c.buf[1:5]))
		if len(c.buf) < 5+n {
			break
		}
		frame := c.buf[:5+n]
		c.buf = c.buf[5+n:]
		// frame: 1B type, 4B len, 8B off, 32B hash, data...
		if frame[0] == byte(msgLeaf) && n >= 48 {
			frame[45+3] ^= 0xFF
		}
		if _, err := c.next(frame); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// syncOnce runs one Serve/Pull session over a fresh pipe pair and
// reports the synced index, the total bytes transferred in both
// directions, and the first error from either side.
func syncOnce(t *testing.T, srv *Index, dst *memSink, prior *Index, corrupt bool) (*Index, int64, error) {
	t.Helper()
	a, b := newPair()
	var wire int64
	origRead, origWrite := a.read, a.write
	a.read = func(p []byte) (int, error) {
		n, err := origRead(p)
		wire += int64(n)
		return n, err
	}
	a.write = func(p []byte) (int, error) {
		n, err := origWrite(p)
		wire += int64(n)
		return n, err
	}
	if corrupt {
		c := &corruptLeaf{next: b.write}
		b.write = c.Write
	}
	var wg sync.WaitGroup
	wg.Add(1)
	serveErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		serveErr <- Serve(b, srv)
	}()
	got, err := Pull(a, dst, prior)
	a.close() // unblock any in-flight server I/O
	serr := <-serveErr
	b.close()
	wg.Wait()
	if err == nil {
		err = serr
	}
	return got, wire, err
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestIndexDeterministic(t *testing.T) {
	a, err := NewIndex(bytes.NewBufferString("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIndex(bytes.NewBufferString("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Root() != b.Root() {
		t.Fatal("same content, different roots")
	}
	if a.Root() == (Hash{}) {
		t.Fatal("non-empty file with zero root")
	}
	if a.Size() != 11 {
		t.Fatalf("size = %d, want 11", a.Size())
	}
	c, _ := NewIndex(bytes.NewBufferString("hello worle"))
	if a.Root() == c.Root() {
		t.Fatal("different content, same root")
	}
	e, err := NewIndex(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if e.Root() != (Hash{}) {
		t.Fatal("empty file must have the zero root")
	}
	if e.Size() != 0 {
		t.Fatalf("empty size = %d", e.Size())
	}
}

func TestSyncNoOp(t *testing.T) {
	data := pattern(3 * chunkSize)
	ix, err := NewIndex(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{data: append([]byte(nil), data...)}
	got, wire, err := syncOnce(t, ix, sink, ix, false)
	if err != nil {
		t.Fatal(err)
	}
	if wire >= 128 {
		t.Fatalf("no-op sync transferred %d bytes, want < 128", wire)
	}
	if got != ix {
		t.Fatal("unchanged sync must return the prior index")
	}
	if !bytes.Equal(sink.data, data) {
		t.Fatal("unchanged sync modified the destination")
	}
}

func TestSyncDelta(t *testing.T) {
	const chunks = 100
	old := pattern(chunks * chunkSize)
	nw := append([]byte(nil), old...)
	// change one chunk in the middle
	for i := 50 * chunkSize; i < 51*chunkSize; i++ {
		nw[i] ^= 0x5A
	}
	srv, err := NewIndex(bytes.NewReader(nw))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := NewIndex(bytes.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{data: append([]byte(nil), old...)}
	got, wire, err := syncOnce(t, srv, sink, prior, false)
	if err != nil {
		t.Fatal(err)
	}
	if wire >= 2*chunkSize {
		t.Fatalf("delta sync transferred %d bytes, want < %d (two chunks)", wire, 2*chunkSize)
	}
	if !bytes.Equal(sink.data, nw) {
		t.Fatal("pulled file differs from the server's")
	}
	if got.Root() != srv.Root() {
		t.Fatal("synced root differs from the server's")
	}
}

func TestSyncFromScratch(t *testing.T) {
	data := pattern(3 * chunkSize)
	srv, err := NewIndex(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	got, wire, err := syncOnce(t, srv, sink, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.data, data) {
		t.Fatal("from-scratch sync produced the wrong content")
	}
	if got.Root() != srv.Root() {
		t.Fatal("from-scratch root mismatch")
	}
	// exact cost: hello(45) + ack(50) + 3 leaf frames(65581 each)
	if want := int64(45 + 50 + 3*(5+40+chunkSize)); wire != want {
		t.Fatalf("from-scratch wire = %d, want %d", wire, want)
	}
}

func TestSyncCorruption(t *testing.T) {
	data := pattern(2 * chunkSize)
	srv, err := NewIndex(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	_, _, err = syncOnce(t, srv, sink, nil, true)
	if err != ErrMismatch {
		t.Fatalf("corrupted transfer: err = %v, want ErrMismatch", err)
	}
}

func TestSyncShrinkAndGrow(t *testing.T) {
	small := pattern(chunkSize)
	big := pattern(3 * chunkSize)
	smallIx, _ := NewIndex(bytes.NewReader(small))
	bigIx, _ := NewIndex(bytes.NewReader(big))

	t.Run("shrink", func(t *testing.T) {
		sink := &memSink{data: append([]byte(nil), big...)}
		got, _, err := syncOnce(t, smallIx, sink, bigIx, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sink.data, small) {
			t.Fatal("shrink did not produce the server's content")
		}
		if got.Root() != smallIx.Root() {
			t.Fatal("shrink root mismatch")
		}
	})
	t.Run("grow", func(t *testing.T) {
		sink := &memSink{data: append([]byte(nil), small...)}
		got, _, err := syncOnce(t, bigIx, sink, smallIx, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sink.data, big) {
			t.Fatal("grow did not produce the server's content")
		}
		if got.Root() != bigIx.Root() {
			t.Fatal("grow root mismatch")
		}
	})
}

func TestSyncOddChunkCount(t *testing.T) {
	// 2 full chunks + a short one: 3 leaves, which exercises the
	// promoted-node path of the tree.
	data := pattern(2*chunkSize + 1000)
	srv, err := NewIndex(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Size() != int64(len(data)) {
		t.Fatalf("size = %d, want %d", srv.Size(), len(data))
	}
	// from scratch
	sink := &memSink{}
	got, _, err := syncOnce(t, srv, sink, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.data, data) {
		t.Fatal("odd-count from-scratch content mismatch")
	}
	if got.Root() != srv.Root() {
		t.Fatal("odd-count root mismatch")
	}
	// delta: change the short chunk
	nw := append([]byte(nil), data...)
	nw[2*chunkSize+42] ^= 0xFF
	srv2, _ := NewIndex(bytes.NewReader(nw))
	sink2 := &memSink{data: append([]byte(nil), data...)}
	got2, wire, err := syncOnce(t, srv2, sink2, got, false)
	if err != nil {
		t.Fatal(err)
	}
	if wire >= 2*chunkSize {
		t.Fatalf("odd-count delta transferred %d bytes, want < %d", wire, 2*chunkSize)
	}
	if !bytes.Equal(sink2.data, nw) {
		t.Fatal("odd-count delta content mismatch")
	}
	if got2.Root() != srv2.Root() {
		t.Fatal("odd-count delta root mismatch")
	}
}

// TestPublicSurface pins the package's public interface to the
// minimal set defined for T001: anything new exported requires a
// deliberate decision.
func TestPublicSurface(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg := pkgs["merkle"]
	got := map[string]bool{}
	for _, f := range pkg.Files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(s.Name.Name) {
							got[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if ast.IsExported(n.Name) {
								got[n.Name] = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && ast.IsExported(d.Name.Name) {
					got[d.Name.Name] = true
				}
			}
		}
	}
	want := []string{"ErrMismatch", "ErrProtocol", "Hash", "Index", "NewIndex", "Pull", "Serve", "Sink"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing exported symbol %q", w)
		}
	}
	for g := range got {
		if !contains(want, g) {
			t.Errorf("unexpected exported symbol %q", g)
		}
	}
	// the two methods an Index exposes
	for _, m := range []string{"Root", "Size"} {
		found := false
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv == nil {
					continue
				}
				if fd.Name.Name == m {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("missing Index method %q", m)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
