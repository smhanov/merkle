# merkle

Efficient file synchronization over any bidirectional byte channel, using a
chunked merkle tree.

A file is split into fixed 64 KiB chunks; a SHA-256 merkle tree over the
chunk hashes authenticates every byte of the file. Two peers reconcile
their trees by exchanging hashes only along the paths that differ, then
transfer only the chunks that actually changed:

- an **unchanged** file transfers nothing but ~100 bytes of handshake;
- a file with **a few changed chunks** transfers exactly those chunks,
  each verified by hash on arrival;
- a **missing** local file transfers the whole file, chunk by chunk.

There is nothing to configure: chunking and hashing are fixed, and peers
running different versions of the package degrade gracefully to a full
transfer.

## API

```go
// Index a file from any reader.
ix, err := merkle.NewIndex(r)

// ix.Root() changes when any byte of the file changes — compare roots
// to detect changes. ix.Size() is the file length.

// Server side: serve the indexed file over any io.ReadWriter
// (a TCP connection, a pipe, or a stream pair bridging HTTP).
err = merkle.Serve(conn, ix)

// Client side: bring a local file up to date. prior is the index of
// the current local file, or nil if the file is absent. Returns the
// index of the synced file, ready to use as prior next time.
newIx, err := merkle.Pull(conn, file, prior)
```

`*os.File` satisfies `merkle.Sink` (the client-side write target), which
is all the client needs. If the file is unchanged, `Pull` returns the
prior index and leaves the file untouched.

## How the sync works

One session per `Serve`/`Pull` call over the channel:

1. The client sends the size and root of its local file (zero root if
   the file is absent).
2. Roots equal → the server replies and nothing else is sent.
3. Sizes differ, or the client has no file → the server streams every
   chunk.
4. Otherwise the two sides descend the tree together: each round the
   server asks for the hashes of the children of the subtrees that still
   differ, and the client answers. This pinpoints the changed chunks
   in ≤ log2(n) rounds without ever transferring a chunk or a full
   hash table.
5. The server sends the changed chunks, each with its offset and hash.
   The client writes them at their offsets, verifies each hash, and
   checks that its rebuilt root matches the server's announced root.

Wire format (internal, for reference): 1-byte type + 4-byte big-endian
length + payload, in both directions; message types are
hello / query / reply / ack / leaf.

## Status

Core package: indexing and sync are implemented and tested (determinism,
no-op / delta / from-scratch / shrink / grow / odd chunk counts,
corruption detection, wire-byte budgets).

Not yet included (see `.plans/`): TCP/HTTP transport adapters,
disk-backed indexes for very large files.

## Notes

- An `Index` holds the file's bytes in memory so it can serve them;
  for very large files, index it once and reuse the `Index` across
  sessions rather than re-indexing per sync.
- Errors: `ErrMismatch` when a received chunk or final root fails
  verification, `ErrProtocol` for a malformed peer. On error the local
  file may be partially updated; re-`Pull` with the same prior index to
  retry.
