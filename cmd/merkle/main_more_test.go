package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wireFrame builds one protocol frame: 1-byte type, 4-byte big-endian
// length, payload — the framing of protocol.go.
func wireFrame(typ byte, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}

// limitedReader caps each Read to n bytes, splitting frames across
// reads.
type limitedReader struct {
	next *bytes.Reader
	n    int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if len(p) > l.n {
		p = p[:l.n]
	}
	return l.next.Read(p)
}

func TestFrameCounter(t *testing.T) {
	leaf1 := bytes.Repeat([]byte{0x05}, 100) // payload full of type bytes
	leaf2 := make([]byte, 64<<10)
	for i := range leaf2 {
		leaf2[i] = byte(i % 7)
	}
	stream := bytes.Join([][]byte{
		wireFrame(1, bytes.Repeat([]byte{1}, 40)),    // hello
		wireFrame(3, bytes.Repeat([]byte{0x05}, 32)), // reply of type bytes
		wireFrame(5, leaf1),                          // leaf 1
		wireFrame(4, bytes.Repeat([]byte{2}, 45)),    // ack
		wireFrame(5, leaf2),                          // leaf 2
		wireFrame(2, bytes.Repeat([]byte{0x05}, 4)),  // query of type bytes
	}, nil)
	for _, n := range []int{1, 3, 7, 64 << 10, 1 << 20} {
		t.Run(fmt.Sprintf("readsize%d", n), func(t *testing.T) {
			fc := &frameCounter{next: &limitedReader{next: bytes.NewReader(stream), n: n}}
			var got []byte
			for {
				buf := make([]byte, 4096)
				m, err := fc.Read(buf)
				got = append(got, buf[:m]...)
				if err != nil {
					break
				}
			}
			if !bytes.Equal(got, stream) {
				t.Fatal("bytes not passed through unchanged")
			}
			if fc.leaf != 2 {
				t.Fatalf("leaf = %d, want 2", fc.leaf)
			}
		})
	}
}

func TestFrameCountingWriter(t *testing.T) {
	stream := bytes.Join([][]byte{
		wireFrame(1, bytes.Repeat([]byte{1}, 40)),
		wireFrame(5, bytes.Repeat([]byte{0x05}, 100)),
		wireFrame(4, bytes.Repeat([]byte{2}, 45)),
		wireFrame(5, bytes.Repeat([]byte{0x05}, 100)),
	}, nil)
	var buf bytes.Buffer
	fw := &frameCountingWriter{next: &buf}
	for i := 0; i < len(stream); i += 7 {
		end := min(i+7, len(stream))
		if _, err := fw.Write(stream[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if fw.leaf != 2 {
		t.Fatalf("leaf = %d, want 2", fw.leaf)
	}
	if !bytes.Equal(buf.Bytes(), stream) {
		t.Fatal("bytes not passed through unchanged")
	}
}

func TestOneShotLine(t *testing.T) {
	tests := []struct {
		n, m, k int64
		noop    bool
		want    string
	}{
		{0, 0, 0, true, "a -> b: up to date"},
		{100, 3, 5, true, "a -> b: up to date"},
		{1234, 3, 5, false, "a -> b: 1234 bytes transferred (3 of 5 chunks changed)"},
		{1234, 5, 5, false, "a -> b: 1234 bytes transferred (5 of 5 chunks changed)"},
		{1234, 0, 0, false, "a -> b: 1234 bytes transferred"},
	}
	for _, tt := range tests {
		if got := oneShotLine("a", "b", tt.n, tt.m, tt.k, tt.noop); got != tt.want {
			t.Fatalf("oneShotLine(a, b, %d, %d, %d, %v) = %q, want %q", tt.n, tt.m, tt.k, tt.noop, got, tt.want)
		}
	}
}

func TestServeLine(t *testing.T) {
	const size = 320000 // 5 chunks
	const peer = "1.2.3.4:5678"
	tests := []struct {
		name       string
		res        sessionResult
		wasUpdated bool
		want       string
	}{
		{
			name:       "push 2 of 5 changed",
			res:        sessionResult{bytes: 132162, leavesIn: 2, preSize: size, postSize: size},
			wasUpdated: true,
			want:       peer + " -> f.txt: 132162 bytes transferred (2 of 5 chunks changed)",
		},
		{
			name:       "size change, all chunks re-sent",
			res:        sessionResult{bytes: 400000, leavesIn: 7, preSize: size, postSize: 400000},
			wasUpdated: true,
			want:       peer + " -> f.txt: 400000 bytes transferred (7 of 7 chunks changed)",
		},
		{
			name:       "pull N-only",
			res:        sessionResult{bytes: 270503, leavesOut: 5, preSize: size, postSize: size},
			wasUpdated: false,
			want:       peer + " -> f.txt: 270503 bytes transferred",
		},
		{
			name: "up to date, updated side",
			res:  sessionResult{bytes: 160, preSize: size, postSize: size},
			want: peer + " -> f.txt: up to date",
		},
		{
			name: "up to date, source side",
			res:  sessionResult{bytes: 160, preSize: size, postSize: size},
			want: peer + " -> f.txt: up to date",
		},
	}
	for _, tt := range tests {
		if got := serveLine(peer, "f.txt", tt.res, tt.wasUpdated); got != tt.want {
			t.Errorf("%s: serveLine = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestWasUpdatedSide(t *testing.T) {
	const size = 320000
	tests := []struct {
		name string
		res  sessionResult
		want bool
	}{
		{name: "leaves received", res: sessionResult{leavesIn: 2, preSize: size, postSize: size}, want: true},
		{name: "size changed", res: sessionResult{preSize: size, postSize: size + 100}, want: true},
		{name: "source, leaves sent only", res: sessionResult{leavesOut: 5, preSize: size, postSize: size}, want: false},
		{name: "noop", res: sessionResult{preSize: size, postSize: size}, want: false},
	}
	for _, tt := range tests {
		if got := wasUpdatedSide(tt.res); got != tt.want {
			t.Errorf("%s: wasUpdatedSide = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestChunkCount(t *testing.T) {
	for size, want := range map[int64]int64{
		0: 0, 1: 1, 65536: 1, 65537: 2, 131072: 2, 131073: 3, 266669: 5,
	} {
		if got := chunkCount(size); got != want {
			t.Errorf("chunkCount(%d) = %d, want %d", size, got, want)
		}
	}
}

// syncBoth runs one full session over in-memory conns: the source side
// serves srcPath, the updated side pulls into dstPath, both behind
// counting wrappers like the one-shot code paths.
func syncBoth(t *testing.T, srcPath, dstPath string) (updated, source sessionResult, err error) {
	aToB := newBufferedPipe() // updated side -> source side
	bToA := newBufferedPipe() // source side -> updated side
	updatedRW := &countingRW{rw: &pipeConn{rd: bToA, wr: aToB}}
	sourceRW := &countingRW{rw: &pipeConn{rd: aToB, wr: bToA}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var e error
		updated, e = syncFile(updatedRW, roleClient, dstPath)
		if e != nil && err == nil {
			err = e
		}
	}()
	source, e := syncFile(sourceRW, roleSource, srcPath)
	if e != nil && err == nil {
		err = e
	}
	aToB.w.Close()
	bToA.w.Close()
	<-done
	return updated, source, err
}

func TestSyncFile(t *testing.T) {
	const wantChunks = 5
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.txt")
	dstPath := filepath.Join(dir, "dst.txt")
	data := bytes.Repeat([]byte("0123456789abcdef"), 20000) // 320000 B, 5 chunks
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("fresh fetch", func(t *testing.T) {
		u, s, err := syncBoth(t, srcPath, dstPath)
		if err != nil {
			t.Fatalf("syncBoth: %v", err)
		}
		got, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("dst content != src content")
		}
		if u.preSize != 0 || u.postSize != int64(len(data)) {
			t.Fatalf("sizes = %d/%d, want 0/%d", u.preSize, u.postSize, len(data))
		}
		if u.leavesIn != wantChunks || s.leavesOut != wantChunks {
			t.Fatalf("leaves in/out = %d/%d, want %d/%d", u.leavesIn, s.leavesOut, wantChunks, wantChunks)
		}
		if u.bytes != s.bytes {
			t.Fatalf("byte totals differ: %d vs %d", u.bytes, s.bytes)
		}
	})

	t.Run("no-op", func(t *testing.T) {
		u, s, err := syncBoth(t, srcPath, dstPath)
		if err != nil {
			t.Fatalf("syncBoth: %v", err)
		}
		if u.leavesIn != 0 || s.leavesOut != 0 {
			t.Fatalf("leaves in/out = %d/%d, want 0/0", u.leavesIn, s.leavesOut)
		}
		if u.preSize != u.postSize {
			t.Fatalf("sizes changed: %d -> %d", u.preSize, u.postSize)
		}
		if line := oneShotLine("src", "dst", u.bytes, u.leavesIn, chunkCount(u.postSize), u.leavesIn == 0 && u.preSize == u.postSize); line != "src -> dst: up to date" {
			t.Fatalf("line = %q", line)
		}
	})

	t.Run("one-chunk delta", func(t *testing.T) {
		data[70000] ^= 0xFF // one byte in chunk 1
		if err := os.WriteFile(srcPath, data, 0644); err != nil {
			t.Fatal(err)
		}
		u, s, err := syncBoth(t, srcPath, dstPath)
		if err != nil {
			t.Fatalf("syncBoth: %v", err)
		}
		got, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("dst content != src content")
		}
		if u.leavesIn != 1 || s.leavesOut != 1 {
			t.Fatalf("leaves in/out = %d/%d, want 1/1", u.leavesIn, s.leavesOut)
		}
		want := fmt.Sprintf("src -> dst: %d bytes transferred (1 of %d chunks changed)", u.bytes, wantChunks)
		if line := oneShotLine("src", "dst", u.bytes, u.leavesIn, chunkCount(u.postSize), false); line != want {
			t.Fatalf("line = %q, want %q", line, want)
		}
	})

	t.Run("source absent", func(t *testing.T) {
		_, _, err := syncBoth(t, filepath.Join(dir, "missing.txt"), dstPath)
		if err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("err = %v, want no such file", err)
		}
	})
}
