package merkle

import (
	"encoding/binary"
	"io"
)

// The sync protocol. One session per call to Serve/Pull, over a
// bidirectional byte channel:
//
//	client: hello{size,root[,chunk]}
//	server: query{refs}  → client: reply{hashes}   (repeated: the descent)
//	server: ack{match,leaves,root,size}
//	server: leaf{off,hash,data} × leaves
//
// A size mismatch or a zero client root skips the descent (full
// transfer). A matching root yields an ack alone. Framing is 1 byte
// type + 4 byte big-endian length + payload, in both directions.
// The hello is 40 bytes; a client that wants a non-default chunk size
// appends 8 bytes carrying it, and the server re-chunks its index to
// match before the descent.

type msgType uint8

const (
	msgHello msgType = iota + 1
	msgQuery
	msgReply
	msgAck
	msgLeaf
)

const maxFrame = 1 << 20 // a chunk plus overhead, with room to spare

// maxBatch caps the refs in one query frame and the hashes in its reply:
// 4 + 32*maxBatch stays under maxFrame, so a descent level with a larger
// frontier is split across multiple query/reply round-trips.
const maxBatch = 32765

type helloMsg struct {
	size  int64
	root  Hash
	chunk int64 // 0 or DefaultChunkSize encodes as the classic 40-byte hello
}

// ref names a subtree by the byte range it covers. Both peers share
// one tree shape for a given size, so a ref is unambiguous.
type ref struct {
	off  int64
	size int64
}

type queryMsg struct{ refs []ref }
type replyMsg struct{ hashes []Hash }

type ackMsg struct {
	match  bool
	leaves uint32
	root   Hash
	size   int64
}

type leafMsg struct {
	off  int64
	hash Hash
	data []byte
}

func writeMsg(w io.Writer, t msgType, p []byte) error {
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	return nil
}

func readMsg(r io.Reader) (msgType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, ErrProtocol
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return msgType(hdr[0]), p, nil
}

func encodeHello(m helloMsg) []byte {
	if m.chunk <= 0 || m.chunk == DefaultChunkSize {
		p := make([]byte, 8+32)
		binary.BigEndian.PutUint64(p[0:8], uint64(m.size))
		copy(p[8:], m.root[:])
		return p
	}
	p := make([]byte, 8+32+8)
	binary.BigEndian.PutUint64(p[0:8], uint64(m.size))
	copy(p[8:], m.root[:])
	binary.BigEndian.PutUint64(p[40:48], uint64(m.chunk))
	return p
}

func decodeHello(p []byte) (helloMsg, error) {
	switch len(p) {
	case 8 + 32:
		// Classic hello: the peer wants the default grid.
		return helloMsg{
			size:  int64(binary.BigEndian.Uint64(p[0:8])),
			root:  Hash(p[8 : 8+32]),
			chunk: DefaultChunkSize,
		}, nil
	case 8 + 32 + 8:
		m := helloMsg{
			size:  int64(binary.BigEndian.Uint64(p[0:8])),
			root:  Hash(p[8 : 8+32]),
			chunk: int64(binary.BigEndian.Uint64(p[40:48])),
		}
		if m.chunk <= 0 {
			return helloMsg{}, ErrProtocol
		}
		return m, nil
	default:
		return helloMsg{}, ErrProtocol
	}
}

func encodeQuery(m queryMsg) []byte {
	p := make([]byte, 4, 4+16*len(m.refs))
	binary.BigEndian.PutUint32(p, uint32(len(m.refs)))
	for _, r := range m.refs {
		var b [16]byte
		binary.BigEndian.PutUint64(b[0:8], uint64(r.off))
		binary.BigEndian.PutUint64(b[8:16], uint64(r.size))
		p = append(p, b[:]...)
	}
	return p
}

func decodeQuery(p []byte) (queryMsg, error) {
	if len(p) < 4 || (len(p)-4)%16 != 0 {
		return queryMsg{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint32(p[0:4]))
	if 4+16*n != len(p) {
		return queryMsg{}, ErrProtocol
	}
	m := queryMsg{refs: make([]ref, n)}
	for i := range m.refs {
		m.refs[i].off = int64(binary.BigEndian.Uint64(p[4+16*i : 12+16*i]))
		m.refs[i].size = int64(binary.BigEndian.Uint64(p[12+16*i : 20+16*i]))
	}
	return m, nil
}

func encodeReply(m replyMsg) []byte {
	p := make([]byte, 4, 4+32*len(m.hashes))
	binary.BigEndian.PutUint32(p, uint32(len(m.hashes)))
	for _, h := range m.hashes {
		p = append(p, h[:]...)
	}
	return p
}

func decodeReply(p []byte) (replyMsg, error) {
	if len(p) < 4 || (len(p)-4)%32 != 0 {
		return replyMsg{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint32(p[0:4]))
	if 4+32*n != len(p) {
		return replyMsg{}, ErrProtocol
	}
	m := replyMsg{hashes: make([]Hash, n)}
	for i := range m.hashes {
		copy(m.hashes[i][:], p[4+32*i:])
	}
	return m, nil
}

func encodeAck(m ackMsg) []byte {
	p := make([]byte, 1+4+32+8)
	if m.match {
		p[0] = 1
	}
	binary.BigEndian.PutUint32(p[1:5], m.leaves)
	copy(p[5:37], m.root[:])
	binary.BigEndian.PutUint64(p[37:45], uint64(m.size))
	return p
}

func decodeAck(p []byte) (ackMsg, error) {
	if len(p) != 1+4+32+8 {
		return ackMsg{}, ErrProtocol
	}
	return ackMsg{
		match:  p[0] == 1,
		leaves: binary.BigEndian.Uint32(p[1:5]),
		root:   Hash(p[5 : 5+32]),
		size:   int64(binary.BigEndian.Uint64(p[37:45])),
	}, nil
}

func encodeLeaf(m leafMsg) []byte {
	p := make([]byte, 8+32, 8+32+len(m.data))
	binary.BigEndian.PutUint64(p[0:8], uint64(m.off))
	copy(p[8:40], m.hash[:])
	return append(p, m.data...)
}

func decodeLeaf(p []byte) (leafMsg, error) {
	if len(p) < 8+32 {
		return leafMsg{}, ErrProtocol
	}
	m := leafMsg{
		off:  int64(binary.BigEndian.Uint64(p[0:8])),
		hash: Hash(p[8 : 8+32]),
		data: p[40:],
	}
	if m.off < 0 {
		return leafMsg{}, ErrProtocol
	}
	return m, nil
}
