// Package merkle synchronizes files over any bidirectional byte channel
// using a chunked merkle tree.
//
// Indexing: NewIndex returns an Index over an io.ReaderAt of the given
// size: a SHA-256 merkle tree over fixed-size chunks (64 KiB by
// default, negotiable per sync — see NewIndexChunked). The Index never
// holds the file's bytes: it reads them only when a hash or a chunk
// needs them, and memoizes computed hashes in a temp file that Close
// removes. Its Root changes when any byte of the file changes —
// compare Roots to detect changes without re-syncing.
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
// Chunking and hashing are fixed (SHA-256); the chunk size is 64 KiB
// unless a peer negotiates another size in the hello (see
// NewIndexChunked). A peer running an older version of the package
// keeps the 64 KiB grid: the server re-chunks to whatever the client
// asks, so mixed versions still sync correctly.
package merkle
