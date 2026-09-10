package merkle

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// Hash is the SHA-256 digest of a file chunk or a merkle subtree.
// The zero Hash identifies the empty file.
type Hash [32]byte

// chunkSize is the fixed leaf size. Peers run the same package, so they
// always chunk identically; a version skew changes the tree shape and
// degrades a sync to a full transfer.
const chunkSize = 64 << 10

// Index is the chunked merkle index of a file. It never holds the
// file's bytes: it reads them on demand from its io.ReaderAt and
// memoizes computed hashes in a temp file. Build one with NewIndex and
// release it with Close.
type Index struct {
	size   int64
	r      io.ReaderAt
	memo   *os.File
	levels []levelMeta
	buf    []byte
	closed bool
}

// levelMeta holds the node count of one tree level and the byte offset
// of its entries in the memo (level-major, 32 bytes per node).
type levelMeta struct {
	n   int
	off int64
}

// treeMeta computes the per-level node counts, memo offsets, and total
// memo size for a file of the given size: n_0 = ceil(size/chunkSize),
// n_{k+1} = ceil(n_k/2), up to the single root.
func treeMeta(size int64) (levels []levelMeta, total int64) {
	n := (size + chunkSize - 1) / chunkSize
	for n > 0 {
		levels = append(levels, levelMeta{n: int(n)})
		if n == 1 {
			break
		}
		n = (n + 1) / 2
	}
	var sum int64
	for i := range levels {
		levels[i].off = 32 * sum
		sum += int64(levels[i].n)
	}
	return levels, 32 * sum
}

// NewIndex returns the index of a size-byte file readable from r. It
// performs no I/O: the file is read only when a hash or a chunk needs
// it, and computed hashes are memoized in a temp file. Call Close to
// remove it.
func NewIndex(r io.ReaderAt, size int64) (*Index, error) {
	if size < 0 {
		return nil, fmt.Errorf("merkle: negative size %d", size)
	}
	levels, total := treeMeta(size)
	f, err := os.CreateTemp("", "merkle-*")
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(total); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &Index{
		size:   size,
		r:      r,
		memo:   f,
		levels: levels,
		buf:    make([]byte, chunkSize),
	}, nil
}

// Close removes the memo temp file and closes it. It is idempotent.
func (ix *Index) Close() error {
	if ix == nil || ix.closed {
		return nil
	}
	ix.closed = true
	if ix.memo == nil {
		return nil
	}
	name := ix.memo.Name()
	err := ix.memo.Close()
	os.Remove(name)
	return err
}

// Root returns the hash of the whole file. It changes when any byte
// changes. The Root of an empty file is the zero Hash. Computing it
// hashes the whole file once; later calls are memo hits.
func (ix *Index) Root() Hash {
	if ix.size == 0 {
		return Hash{}
	}
	h, _ := ix.hashNode(len(ix.levels)-1, 0)
	return h
}

// Size returns the length of the indexed file in bytes.
func (ix *Index) Size() int64 {
	return ix.size
}

// rangeOf returns the byte range [off, off+size) of the node
// (level, index). Every node boundary is a multiple of chunkSize; a
// promoted (single-child) node covers exactly its child's range, which
// is why the span is capped by the file end.
func (ix *Index) rangeOf(lvl, i int) (off, size int64) {
	w := int64(1) << uint(lvl) * chunkSize
	off = int64(i) * w
	size = min(w, ix.size-off)
	return off, size
}

// nodeForRange resolves a byte range to (level, index): the smallest
// level whose node covers exactly [off, off+size). A range matched by a
// promoted node and its child resolves to either level; both carry the
// same hash, so the answer is unique.
func (ix *Index) nodeForRange(off, size int64) (int, int, bool) {
	if size < 0 || off < 0 || off+size > ix.size || off%chunkSize != 0 {
		return 0, 0, false
	}
	for l := 0; l < len(ix.levels); l++ {
		w := int64(1) << uint(l) * chunkSize
		if off%w != 0 {
			continue
		}
		i := int(off / w)
		if i >= ix.levels[l].n {
			continue
		}
		_, sz := ix.rangeOf(l, i)
		if sz == size {
			return l, i, true
		}
	}
	return 0, 0, false
}

// hashRange returns the hash of the node covering exactly
// [off, off+size), or false if no such node exists.
func (ix *Index) hashRange(off, size int64) (Hash, bool) {
	lvl, i, ok := ix.nodeForRange(off, size)
	if !ok {
		return Hash{}, false
	}
	h, err := ix.hashNode(lvl, i)
	if err != nil {
		return Hash{}, false
	}
	return h, true
}

// hashNode returns the hash of the node at (level, index), computing
// and memoizing it if needed. The single buf is safe to share: it is
// read and consumed at leaves before any parent combines its children.
func (ix *Index) hashNode(lvl, i int) (Hash, error) {
	p := ix.levels[lvl].off + int64(i)*32
	var h Hash
	if _, err := ix.memo.ReadAt(h[:], p); err != nil {
		return Hash{}, err
	}
	if h != (Hash{}) {
		return h, nil
	}
	var err error
	switch {
	case lvl == 0:
		off, sz := ix.rangeOf(0, i)
		n, rerr := ix.r.ReadAt(ix.buf[:sz], off)
		if rerr != nil && rerr != io.EOF {
			return Hash{}, rerr
		}
		h = hash(ix.buf[:n])
	case ix.levels[lvl-1].n > 2*i+1:
		if h, err = ix.hashTwo(lvl-1, 2*i); err != nil {
			return Hash{}, err
		}
	default: // promoted: single child, hash carried verbatim
		if h, err = ix.hashNode(lvl-1, 2*i); err != nil {
			return Hash{}, err
		}
	}
	if _, err := ix.memo.WriteAt(h[:], p); err != nil {
		return Hash{}, err
	}
	return h, nil
}

// hashTwo returns the hash of a two-child node, recursing into both
// children first.
func (ix *Index) hashTwo(lvl, i int) (Hash, error) {
	a, err := ix.hashNode(lvl, i)
	if err != nil {
		return Hash{}, err
	}
	b, err := ix.hashNode(lvl, i+1)
	if err != nil {
		return Hash{}, err
	}
	return hashChildren([]Hash{a, b}), nil
}

// recompute rewrites the memo entry of the node at (level, index) from
// its children, which must already be up to date.
func (ix *Index) recompute(lvl, i int) error {
	c := ix.levels[lvl-1]
	p := ix.levels[lvl].off + int64(i)*32
	var h Hash
	if c.n > 2*i+1 {
		var a, b Hash
		if _, err := ix.memo.ReadAt(a[:], c.off+int64(2*i)*32); err != nil {
			return err
		}
		if _, err := ix.memo.ReadAt(b[:], c.off+int64(2*i+1)*32); err != nil {
			return err
		}
		h = hashChildren([]Hash{a, b})
	} else {
		if _, err := ix.memo.ReadAt(h[:], c.off+int64(2*i)*32); err != nil {
			return err
		}
	}
	_, err := ix.memo.WriteAt(h[:], p)
	return err
}

// patchAncestors recomputes, level by level, every node that is an
// ancestor of a changed leaf.
func (ix *Index) patchAncestors(changed map[int]bool) error {
	for lvl := 1; lvl < len(ix.levels); lvl++ {
		next := make(map[int]bool)
		for i := range changed {
			next[i/2] = true
		}
		for i := range next {
			if err := ix.recompute(lvl, i); err != nil {
				return err
			}
		}
		changed = next
	}
	return nil
}

// computeAllLevels rebuilds every memo entry above the leaf level from
// the leaf entries, without reading the file.
func (ix *Index) computeAllLevels() error {
	for lvl := 1; lvl < len(ix.levels); lvl++ {
		for i := 0; i < ix.levels[lvl].n; i++ {
			if err := ix.recompute(lvl, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// setLayout adopts a new file size: it resizes the memo to the new
// level layout (all entries zero) and updates the shape arithmetic.
func (ix *Index) setLayout(size int64) error {
	levels, total := treeMeta(size)
	if ix.memo == nil {
		f, err := os.CreateTemp("", "merkle-*")
		if err != nil {
			return err
		}
		ix.memo = f
	}
	if err := ix.memo.Truncate(total); err != nil {
		return err
	}
	ix.levels = levels
	ix.size = size
	return nil
}

// hash returns the digest of b.
func hash(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

// hashChildren returns the digest of the concatenation of child
// digests: the hash of an internal node.
func hashChildren(cs []Hash) Hash {
	buf := make([]byte, 0, 32*len(cs))
	for _, c := range cs {
		buf = append(buf, c[:]...)
	}
	return Hash(sha256.Sum256(buf))
}
