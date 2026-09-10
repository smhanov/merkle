package merkle

import (
	"crypto/sha256"
	"io"
	"sort"
)

// Hash is the SHA-256 digest of a file chunk or a merkle subtree.
// The zero Hash identifies the empty file.
type Hash [32]byte

// chunkSize is the fixed leaf size. Peers run the same package, so they
// always chunk identically; a version skew changes the tree shape and
// degrades a sync to a full transfer.
const chunkSize = 64 << 10

// node is one subtree of the merkle tree: its hash, the byte range of
// the file it covers, and the indices of its children in the level
// below (0 for a leaf).
type node struct {
	h     Hash
	off   int64
	size  int64
	child []int
}

// level is one stratum of the tree; levels[0] holds the leaf (chunk)
// nodes, the last level holds the root.
type level struct {
	nodes []node
}

// Index is the chunked merkle index of a file. It holds the file's
// bytes and the tree over them, so it can answer hash queries and
// serve the data. Build one with NewIndex.
type Index struct {
	size   int64
	data   []byte
	levels []level
}

// NewIndex reads r fully and returns the index of its content.
func NewIndex(r io.Reader) (*Index, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	n := chunkCount(len(data))
	hs := make([]Hash, n)
	for i := range hs {
		hs[i] = hash(data[i*chunkSize : min(i*chunkSize+chunkSize, len(data))])
	}
	return indexFrom(data, hs), nil
}

// indexFrom assembles an Index from the file bytes and the hash of
// each chunk. It is shared by NewIndex and by Pull, which reuses it to
// splice changed chunks without re-hashing the rest of the file.
func indexFrom(data []byte, leafHashes []Hash) *Index {
	ix := &Index{size: int64(len(data)), data: data}
	if len(leafHashes) == 0 {
		return ix
	}
	lev := level{}
	for i, h := range leafHashes {
		start := i * chunkSize
		end := min(start+chunkSize, len(data))
		lev.nodes = append(lev.nodes, node{h: h, off: int64(start), size: int64(end - start)})
	}
	ix.levels = append(ix.levels, lev)
	for len(ix.levels[len(ix.levels)-1].nodes) > 1 {
		ix.levels = append(ix.levels, pair(ix.levels[len(ix.levels)-1]))
	}
	return ix
}

// pair builds the level above l by pairing adjacent nodes; an odd
// trailing node is promoted unchanged, as in the canonical merkle
// construction.
func pair(l level) level {
	out := level{}
	for i := 0; i < len(l.nodes); i++ {
		if i+1 < len(l.nodes) {
			a, b := l.nodes[i], l.nodes[i+1]
			out.nodes = append(out.nodes, node{
				h:     hashChildren([]Hash{a.h, b.h}),
				off:   a.off,
				size:  b.off + b.size - a.off,
				child: []int{i, i + 1},
			})
			i++
		} else {
			a := l.nodes[i]
			out.nodes = append(out.nodes, node{h: a.h, off: a.off, size: a.size, child: []int{i}})
		}
	}
	return out
}

// Root returns the hash of the whole file. It changes when any byte
// changes. The Root of an empty file is the zero Hash.
func (ix *Index) Root() Hash {
	if len(ix.levels) == 0 {
		return Hash{}
	}
	return ix.levels[len(ix.levels)-1].nodes[0].h
}

// Size returns the length of the indexed file in bytes.
func (ix *Index) Size() int64 {
	return ix.size
}

// lookup returns the hash of the node covering exactly
// [off, off+size), or false if no such node exists. A promoted node
// shares its range with its child, so the match may come from either
// level; both carry the same hash.
func (ix *Index) lookup(off, size int64) (Hash, bool) {
	for l := range ix.levels {
		nodes := ix.levels[l].nodes
		i := sort.Search(len(nodes), func(j int) bool { return nodes[j].off >= off })
		if i < len(nodes) && nodes[i].off == off && nodes[i].size == size {
			return nodes[i].h, true
		}
	}
	return Hash{}, false
}

// chunkCount is the number of chunkSize chunks needed to hold n bytes.
func chunkCount(n int) int {
	return (n + chunkSize - 1) / chunkSize
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
