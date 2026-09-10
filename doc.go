// Package merkle synchronizes files over any bidirectional byte channel
// using a chunked merkle tree.
//
// Indexing: NewIndex reads an io.Reader and returns an Index: a SHA-256
// merkle tree over fixed 64 KiB chunks. The Index holds the file's bytes
// so it can serve them later, and its Root changes when any byte of the
// file changes — compare Roots to detect changes without re-syncing.
//
// Syncing: a server calls Serve over an io.ReadWriter (a TCP connection,
// an in-memory pipe, or a stream pair bridging HTTP); a client calls
// Pull against a Sink (*os.File satisfies it), passing its current Index
// or nil if the file is absent. The peers exchange only the hashes
// along the paths that differ, then only the chunks that actually
// changed:
//
//   - an unchanged file transfers nothing but ~100 bytes of handshake;
//   - a file with a few changed chunks transfers exactly those chunks,
//     each verified by hash on arrival;
//   - a missing local file transfers the whole file, chunk by chunk.
//
// Chunking and hashing are fixed (64 KiB, SHA-256): there is nothing to
// configure. Peers running different versions of the package degrade
// gracefully to a full transfer.
package merkle
