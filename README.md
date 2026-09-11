# merkle

Efficient file synchronization over any bidirectional byte channel, using a
chunked merkle tree.

An unchanged file costs about 100 bytes. A file with a few changed chunks
costs exactly those chunks. A missing file costs the whole file. There is
nothing to configure and nothing kept on disk between runs.

## How it works

### The merkle tree

A file is split into fixed 64 KiB chunks (the last one may be shorter).
Each chunk is SHA-256 hashed. Those chunk hashes are paired and hashed
together, the results paired and hashed again, level by level, until a
single root hash remains. This is the content-hashing idea behind git,
IPFS, bup, and ZFS: data is made verifiable by the hashes that cover it.

The property that makes sync cheap: **a subtree's hash authenticates every
byte beneath it.** If two files produce the same hash for the same subtree,
those bytes are identical — provable without reading either file. And if
any one byte inside a subtree changes, the hash of that subtree, and every
hash above it, changes. The tree therefore localizes a change to the
smallest subtree that contains it.

### The sync

One session runs over any bidirectional byte channel — a TCP connection,
an in-memory pipe:

1. The client sends the size and root of its local file (a zero root if
   the file is absent).
2. Roots and sizes match → the server replies and nothing else is sent.
3. Sizes differ, or the client has no file → the server streams every
   chunk.
4. Otherwise the two sides descend the tree together: each round the
   server asks for the hashes of the children of the subtrees that still
   differ, and the client answers. This pinpoints the changed chunks in
   ≤ log2(n) rounds, exchanging only hash bytes — never chunk data and
   never the whole hash table.
5. The server sends the changed chunks, each with its offset and hash.
   The client writes them at their offsets, verifies each chunk's hash,
   and checks that its rebuilt root matches the server's announced root.

Internal nodes never cross the wire — their hashes are recomputable from
the children — so only leaf data and leaf hashes are transferred, the
minimum possible for chunked sync. The wire format is internal: 1-byte
type + 4-byte big-endian length + payload, in both directions (message
types: hello / query / reply / ack / leaf). For files with thousands of
chunks the query and reply frames are batched (32,765 refs each) to stay
under the 1 MiB frame cap; a tree that fits one batch sends byte-identical
frames to an unbatched one.

## Why it's efficient

These figures are asserted in the test suite, not benchmarks:

- **No change.** Re-syncing an unchanged 3-chunk file moves **95 bytes**
  on the wire (the hello and the ack) and leaves the destination file
  untouched.
- **One chunk changed.** A 100-chunk (~6.25 MiB) file with a single 64 KiB
  chunk edited transfers **66,642 bytes** — the one chunk plus a kilobyte
  of descent, about 1% of the file — and every received byte is hash-
  verified on arrival.
- **Nothing there.** Fetching a 3-chunk file from scratch costs exactly
  **196,838 bytes**: 45 (hello) + 50 (ack) + 3×65,581 (the three chunk
  frames).
- **Big files stay cheap.** The same one-chunk delta on a **1 TiB** file
  still moves **68,412 bytes**; a full rewrite of a 1 TiB file moves
  everything (1.1 TB). The index of a **1 GiB** file holds **< 1 MiB** of
  memory whether or not the file has been touched yet.

The one honest cost: a session over an *existing* file hashes that file
once, because the client must present its root to prove what it already
has. That is O(file) hashing and O(1) memory per session, with no state
kept between runs (see Costs and caveats).

## Using the package

```go
f, err := os.Open("file")
fi, err := f.Stat()
ix, err := merkle.NewIndex(f, fi.Size()) // lazy: no bytes read yet
defer ix.Close()

// ix.Root() changes when any byte changes — compare roots to detect
// change. ix.Size() is the file length.

// Server: serve the indexed file over any io.ReadWriter.
err = merkle.Serve(conn, ix)

// Client: bring a local file up to date. prior is the index of the
// current local file, or nil if the file is absent. Returns the index of
// the synced file, ready to use as prior next time.
newIx, err := merkle.Pull(conn, file, prior)
```

`*os.File` satisfies both `io.ReaderAt` (indexing) and `merkle.Sink`
(the client write target). If the file is unchanged, `Pull` returns the
prior index and leaves the file untouched.

## The `merkle` CLI

`cmd/merkle` builds `merkle`, a sync CLI used like rsync:

    merkle file.txt smhanov@megos:~/file.txt    # push over ssh
    merkle smhanov@megos:~/file.txt file.txt    # pull over ssh
    merkle file1.txt file1-mirrored.txt         # local mirror

The direction is always `merkle <src> <dst>`: src's content wins and dst
is updated. Local/local runs over an in-process loopback connection.
Pulling is the same command with the argument order reversed.

A remote argument `[user@]host:path` (or `host:path` for the current user)
goes over ssh: the CLI runs
`ssh [user@]host "merkle serve <path> -listen -"` and rides the protocol
over the ssh session's stdio — no daemon, no listening port. ssh provides
auth and encryption and uses the user's ssh config and keys exactly like
`ssh user@host`; it assumes an `ssh` client locally and `merkle` on the
remote PATH. The remote file must exist before a one-shot ssh sync (an
empty file is fine); a missing remote file is a clear error.

`host:NNNN` (all digits after the last colon) is raw TCP to a running
`merkle serve` on that port — loopback/testing only. v1 takes at most one
remote endpoint per command.

Directories sync file by file, in sorted order, over one connection:

    merkle ./site ./site-mirror          # local directory mirror
    merkle ./site smhanov@megos:~/site   # push a tree over ssh

The local target may not exist yet (it is created); pulling a remote
directory is not supported in v1. A per-file failure is reported and the
remaining files still sync.

There is no disk state: every command builds its index when it starts.
`merkle serve <file-or-dir> [-listen addr]` (default `:9000`) is the
resident endpoint: it re-indexes the file per connection, so it always
sees the current file without a restart, and prints a line per connection.
`-listen -` runs one session (or a folder's per-file sessions) on
stdin/stdout and exits — that is the form the ssh mode runs on the remote.

Compression is off by default, like ssh; for a slow link set
`Compression yes` in ssh_config (or `ssh -C`) — the ssh mode rides ssh,
so ssh's compression covers the transfer.

## Costs and caveats

- An `Index` never holds the file's bytes: it reads them on demand from
  its `io.ReaderAt` and memoizes computed hashes in a temp file that
  `Close` removes. Memory is O(tree depth); the memo holds one 32-byte
  hash per node — about 64 bytes per 64 KiB chunk, ~0.1% of a large
  file's size.
- A session over an existing file hashes that file once: the hello carries
  its root, which forces every node. That is the price of stateless change
  detection — nothing is persisted between runs, so there is also nothing
  to go stale.
- Errors: `ErrMismatch` when a received chunk or the final root fails
  verification, `ErrProtocol` for a malformed peer. On error the local
  file may be partially updated; re-`Pull` with the same prior index to
  retry.

## Get it

    go get github.com/smhanov/merkle

Requires Go 1.26 or later. The code is available under the terms in the
[LICENSE](LICENSE) file.
