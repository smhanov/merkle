package merkle

import (
	"io"
	"sort"
)

// Sink is the write target of a Pull: it accepts random-access writes
// and resizing. *os.File satisfies Sink.
type Sink interface {
	io.WriterAt
	Truncate(size int64) error
}

// Serve is the server side of a sync over rw, a bidirectional byte
// channel (a TCP connection, a pipe, or a stream pair bridging HTTP).
// It reconciles the client's file against ix and sends only the chunks
// that differ — nothing when they match, all of them when the client
// has no file or a different size. Serve handles one session.
func Serve(rw io.ReadWriter, ix *Index) error {
	t, p, err := readMsg(rw)
	if err != nil {
		return err
	}
	if t != msgHello {
		return ErrProtocol
	}
	hello, err := decodeHello(p)
	if err != nil {
		return err
	}

	root, err := ix.root()
	if err != nil {
		return err
	}

	if hello.root == root && hello.size == ix.size {
		// Identical: a handshake only, no data.
		return writeMsg(rw, msgAck, encodeAck(ackMsg{match: true, root: root, size: ix.size}))
	}

	var changed []int
	if hello.size != ix.size || hello.root == (Hash{}) {
		// No file, or a different shape: send everything.
		changed = make([]int, ix.levels[0].n)
		for i := range changed {
			changed[i] = i
		}
	} else {
		changed, err = ix.descend(func(refs []ref) ([]Hash, error) {
			return queryPeer(rw, refs)
		})
		if err != nil {
			return err
		}
	}

	ack := ackMsg{leaves: uint32(len(changed)), root: root, size: ix.size}
	if err := writeMsg(rw, msgAck, encodeAck(ack)); err != nil {
		return err
	}
	for _, i := range changed {
		if err := ix.sendLeaf(rw, i); err != nil {
			return err
		}
	}
	return nil
}

// sendLeaf streams the leaf i's frame from the reader through the
// index's reusable buffer.
func (ix *Index) sendLeaf(w io.Writer, i int) error {
	off, sz := ix.rangeOf(0, i)
	h, err := ix.hashNode(0, i)
	if err != nil {
		return err
	}
	if _, err := ix.r.ReadAt(ix.buf[:sz], off); err != nil {
		return err
	}
	return writeMsg(w, msgLeaf, encodeLeaf(leafMsg{off: off, hash: h, data: ix.buf[:sz]}))
}

// Pull is the client side of a sync over rw. It brings dst up to date
// with the server's file: dst is resized as needed and the chunks that
// changed are written into it, each verified by hash. prior is the
// index of the current local file, or nil if the file is absent. Pull
// returns the index of the synced file, ready to use as prior for the
// next sync; when the file is unchanged it returns prior itself and
// dst is left untouched.
func Pull(rw io.ReadWriter, dst Sink, prior *Index) (*Index, error) {
	if prior == nil {
		prior = &Index{} // absent file: zero size, zero root
	}
	if err := writeMsg(rw, msgHello, encodeHello(helloMsg{size: prior.size, root: prior.Root()})); err != nil {
		return nil, err
	}
	for {
		t, p, err := readMsg(rw)
		if err != nil {
			return nil, err
		}
		switch t {
		case msgQuery:
			q, err := decodeQuery(p)
			if err != nil {
				return nil, err
			}
			hs := make([]Hash, len(q.refs))
			for i, r := range q.refs {
				if h, ok := prior.hashRange(r.off, r.size); ok {
					hs[i] = h
				}
			}
			if err := writeMsg(rw, msgReply, encodeReply(replyMsg{hashes: hs})); err != nil {
				return nil, err
			}
		case msgAck:
			ack, err := decodeAck(p)
			if err != nil {
				return nil, err
			}
			if ack.match {
				return prior, nil
			}
			return apply(rw, dst, prior, ack)
		default:
			return nil, ErrProtocol
		}
	}
}

// root returns the file root, hashing the whole file once if the memo
// does not have it yet.
func (ix *Index) root() (Hash, error) {
	if ix.size == 0 {
		return Hash{}, nil
	}
	return ix.hashNode(len(ix.levels)-1, 0)
}

// descend finds the leaf indices of ix that differ from a peer, by
// walking the tree top-down: each round it asks the peer for the
// hashes of the children of the subtrees that still differ. The peer
// callback performs one query/reply round per call.
func (ix *Index) descend(peer func([]ref) ([]Hash, error)) ([]int, error) {
	type fr struct {
		lvl int
		i   int
	}
	frontier := []fr{{lvl: len(ix.levels) - 1, i: 0}}
	for lvl := len(ix.levels) - 1; lvl > 0; lvl-- {
		var refs []ref
		next := make([]fr, 0, len(frontier)*2)
		for _, f := range frontier {
			for c := 2 * f.i; c < 2*f.i+2 && c < ix.levels[lvl-1].n; c++ {
				off, sz := ix.rangeOf(lvl-1, c)
				refs = append(refs, ref{off: off, size: sz})
				next = append(next, fr{lvl: lvl - 1, i: c})
			}
		}
		hs, err := peer(refs)
		if err != nil {
			return nil, err
		}
		if len(hs) != len(refs) {
			return nil, ErrProtocol
		}
		frontier = next[:0]
		for i, f := range next {
			h, err := ix.hashNode(f.lvl, f.i)
			if err != nil {
				return nil, err
			}
			if hs[i] != h {
				frontier = append(frontier, f)
			}
		}
	}
	leaves := make([]int, 0, len(frontier))
	for _, f := range frontier {
		leaves = append(leaves, f.i)
	}
	sort.Ints(leaves)
	return leaves, nil
}

// queryPeer sends one batch of subtree refs to the peer and returns
// the peer's hashes in the same order.
func queryPeer(rw io.ReadWriter, refs []ref) ([]Hash, error) {
	if err := writeMsg(rw, msgQuery, encodeQuery(queryMsg{refs: refs})); err != nil {
		return nil, err
	}
	t, p, err := readMsg(rw)
	if err != nil {
		return nil, err
	}
	if t != msgReply {
		return nil, ErrProtocol
	}
	m, err := decodeReply(p)
	if err != nil {
		return nil, err
	}
	return m.hashes, nil
}

// apply writes the ack.leaves leaf messages from rw into dst and
// patches prior's memo so it indexes the resulting file: same size
// patches the changed leaf entries and their ancestors, a size change
// rebuilds the memo from the received leaves. The final root is
// compared to the ack's. The returned index is prior in both cases.
func apply(rw io.ReadWriter, dst Sink, prior *Index, ack ackMsg) (*Index, error) {
	sameSize := ack.size == prior.size
	if err := dst.Truncate(ack.size); err != nil {
		return nil, err
	}
	if !sameSize {
		if err := prior.setLayout(ack.size); err != nil {
			return nil, err
		}
	}
	changed := make(map[int]bool, ack.leaves)
	for i := 0; i < int(ack.leaves); i++ {
		t, p, err := readMsg(rw)
		if err != nil {
			return nil, err
		}
		if t != msgLeaf {
			return nil, ErrProtocol
		}
		m, err := decodeLeaf(p)
		if err != nil {
			return nil, err
		}
		if hash(m.data) != m.hash {
			return nil, ErrMismatch
		}
		if m.off%chunkSize != 0 {
			return nil, ErrProtocol
		}
		li := int(m.off / chunkSize)
		if li >= prior.levels[0].n {
			return nil, ErrProtocol
		}
		if _, err := dst.WriteAt(m.data, m.off); err != nil {
			return nil, err
		}
		if _, err := prior.memo.WriteAt(m.hash[:], prior.levels[0].off+int64(li)*32); err != nil {
			return nil, err
		}
		changed[li] = true
	}
	var err error
	if sameSize {
		err = prior.patchAncestors(changed)
	} else {
		err = prior.computeAllLevels()
	}
	if err != nil {
		return nil, err
	}
	root, err := prior.root()
	if err != nil {
		return nil, err
	}
	if root != ack.root {
		return nil, ErrMismatch
	}
	return prior, nil
}
