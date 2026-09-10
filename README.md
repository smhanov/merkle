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
// Index a file. The index is lazy: it holds no file bytes, reads them
// only when a hash needs them, and memoizes hashes in a temp file
// (removed by Close), so a terabyte file costs O(tree depth) of memory.
f, err := os.Open("file")
fi, err := f.Stat()
ix, err := merkle.NewIndex(f, fi.Size())
defer ix.Close()

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

`*os.File` satisfies both `io.ReaderAt` (indexing) and `merkle.Sink`
(the client-side write target), which is all the client needs. If the
file is unchanged, `Pull` returns the prior index and leaves the file
untouched.

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

## CLI

`cmd/merkle` builds `merkle`, a single-file sync CLI over the
package, used like rsync:

    merkle file.txt smhanov@megos:~/file.txt    # push over ssh
    merkle file1.txt file1-mirrored.txt         # local mirror

The direction is always `merkle <src> <dst>`: src's content wins,
dst is updated. Local/local runs over an in-process loopback
connection. Pulling is the same command with the argument order
reversed, e.g. `merkle smhanov@megos:~/file.txt file.txt`.

A remote argument `[user@]host:path` (or `host:path` for the current
user) goes over ssh: the CLI runs
`ssh [user@]host "merkle serve <path> -listen -"` and rides the
protocol over the ssh session's stdio — no daemon, no listening
port. ssh provides auth and encryption, and the user's ssh config
and keys are used exactly like with `ssh user@host`; it assumes an
`ssh` client locally and `merkle` on the remote PATH. The remote
file must exist before a one-shot ssh sync (an empty file is fine);
a missing remote file is a clear error.

`host:NNNN` (all digits after the last colon) is raw TCP to a
running `merkle serve` on that port — loopback/testing only.

There is no disk state: every command builds its index when it
starts; nothing persists between runs. `merkle serve <file>
[-listen addr]` (default `:9000`) is the resident endpoint: it
re-indexes the file per connection, so it always sees the current
file without a restart, and reports a line per connection.
`-listen -` runs one session on stdin/stdout and exits; that is the
form the ssh form runs on the remote.

Compression is off by default, like ssh; for slow links set
`Compression yes` in ssh_config (or `ssh -C`) — the ssh form rides
ssh, so ssh's compression covers the transfer.

## Status

Core package: indexing and sync are implemented and tested (determinism,
no-op / delta / from-scratch / shrink / grow / odd chunk counts,
corruption detection, wire-byte budgets).

Not yet included (see `.plans/`): transport adapters.

## Notes

- An `Index` never holds the file's bytes: it reads them on demand from
  its `io.ReaderAt` and memoizes computed hashes in a temp file, removed
  by `Close`. Memory is O(tree depth); the memo is at most 32 bytes per
  64 KiB chunk (~0.1% of a large file's size).
- A session over an existing file hashes it once: the hello carries the
  file's root, which forces every node. That is the cost of stateless
  change detection — nothing is persisted between runs.
- Errors: `ErrMismatch` when a received chunk or final root fails
  verification, `ErrProtocol` for a malformed peer. On error the local
  file may be partially updated; re-`Pull` with the same prior index to
  retry.
