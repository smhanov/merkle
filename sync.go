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

	if hello.root == ix.Root() && hello.size == ix.size {
		// Identical: a handshake only, no data.
		return writeMsg(rw, msgAck, encodeAck(ackMsg{match: true, root: ix.Root(), size: ix.size}))
	}

	var changed []int
	if hello.size != ix.size || hello.root == (Hash{}) {
		// No file, or a different shape: send everything.
		changed = make([]int, len(ix.levels[0].nodes))
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

	ack := ackMsg{leaves: uint32(len(changed)), root: ix.Root(), size: ix.size}
	if err := writeMsg(rw, msgAck, encodeAck(ack)); err != nil {
		return err
	}
	lev := ix.levels[0]
	for _, i := range changed {
		ln := lev.nodes[i]
		if err := writeMsg(rw, msgLeaf, encodeLeaf(leafMsg{off: ln.off, hash: ln.h, data: ix.data[ln.off : ln.off+ln.size]})); err != nil {
			return err
		}
	}
	return nil
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
				if h, ok := prior.lookup(r.off, r.size); ok {
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

// descend finds the leaf indices of ix that differ from a peer, by
// walking the tree top-down: each round it asks the peer for the
// hashes of the children of the subtrees that still differ. The peer
// callback performs one query/reply round per call.
func (ix *Index) descend(peer func([]ref) ([]Hash, error)) ([]int, error) {
	lvl := len(ix.levels) - 1
	frontier := []int{0}
	for lvl > 0 {
		var refs []ref
		next := make([]int, 0, len(frontier)*2)
		for _, ni := range frontier {
			for _, c := range ix.levels[lvl].nodes[ni].child {
				ch := ix.levels[lvl-1].nodes[c]
				refs = append(refs, ref{off: ch.off, size: ch.size})
				next = append(next, c)
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
		for i := range refs {
			if hs[i] != ix.levels[lvl-1].nodes[next[i]].h {
				frontier = append(frontier, next[i])
			}
		}
		lvl--
	}
	sort.Ints(frontier)
	return frontier, nil
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

// apply writes the ack.leaves leaf messages from rw into dst, splices
// them into a working copy of prior's bytes, and returns the index of
// the resulting file.
func apply(rw io.ReadWriter, dst Sink, prior *Index, ack ackMsg) (*Index, error) {
	var data []byte
	if ack.size == prior.size && prior.size > 0 {
		data = append([]byte(nil), prior.data...)
	} else {
		data = make([]byte, ack.size)
	}
	if err := dst.Truncate(ack.size); err != nil {
		return nil, err
	}
	leafHashes := make([]Hash, chunkCount(int(ack.size)))
	if len(prior.levels) > 0 {
		copy(leafHashes, priorLeafHashes(prior))
	}
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
		if _, err := dst.WriteAt(m.data, m.off); err != nil {
			return nil, err
		}
		leafHashes[m.off/chunkSize] = m.hash
		copy(data[m.off:], m.data)
	}
	ix := indexFrom(data, leafHashes)
	if ix.Root() != ack.root {
		return nil, ErrMismatch
	}
	return ix, nil
}

// priorLeafHashes returns the leaf-level hashes of ix.
func priorLeafHashes(ix *Index) []Hash {
	hs := make([]Hash, len(ix.levels[0].nodes))
	for i := range hs {
		hs[i] = ix.levels[0].nodes[i].h
	}
	return hs
}
