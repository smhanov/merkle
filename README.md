# merkle

Efficient file synchronization over any bidirectional channel, using chunked
Merkle trees.

## Status

The package currently defines the protocol and the public API (types and
interfaces). The in-memory index, the sync loop, and the codecs are in
progress.

## How it works

A file is split into fixed-size chunks (default 64 KiB). A binary Merkle
tree over the chunk hashes authenticates every byte of the file: any
subtree's hash covers all of its leaves.

Two peers reconcile their trees by exchanging hashes only along the paths
that differ (an interactive descent, level by level), then transfer only
the changed chunks. Because internal node hashes are deterministic
functions of their children, only leaf data and leaf hashes ever cross
the wire.

Transfer cost:

- **Identical files** — one round trip, zero data.
- **k changed chunks** — those k chunks, plus O(k log n) bytes of hash
  metadata.
- **No local file (from scratch)** — the full file, chunk by chunk, every
  chunk verified by its hash; overhead is a few percent of one chunk.

The sync API is transport-generic: it operates on an `io.ReadWriter`
(a TCP connection, an in-memory pipe, or an adapter over a streaming
HTTP request/response pair) plus a `Codec` that frames the protocol
messages. Indexing takes an `io.Reader`.

## API (target)

```go
// Index a file from any reader.
ix, err := merkle.NewIndexer(merkle.WithChunkSize(1 << 20)).Build(ctx, r)

// Server: serve an authoritative file over any bidirectional channel.
err = merkle.Serve(ctx, link, codec, file, ix)

// Client: bring a local file up to date. localIndex may be nil
// (no file yet). Returns the index of the resulting file for future syncs.
remote, err := merkle.Sync(ctx, link, codec, file, localIndex)
```

`*os.File` satisfies both the server-side `Source` and the client-side
`Sink`.

## Protocol (v1)

| Type      | Direction   | Payload    | Purpose                                          |
| --------- | ----------- | ---------- | ------------------------------------------------ |
| Request   | client→server | `Request` | Client's tree: chunk size, size, root (zero = no file) |
| Query     | server→client | `Query`   | Ask for hashes of the referenced subtrees         |
| Replies   | client→server | `Replies` | Subtree hashes, in query order                    |
| Response  | server→client | `Response`| Reconciliation result; ends the descent          |
| Leaf      | server→client | `Node`    | One chunk: hash, offset, data                     |

Flow: the client sends one `Request`. If the roots match, the server
replies `Response{Match:true}` and nothing else is sent. Otherwise the
server and client descend the tree together: each round the server asks
for the children of the subtrees that still differ, and the client
answers with its own hashes. When the descent reaches the changed
leaves, the server sends a `Response` followed by one `Leaf` message per
changed chunk (or all chunks, when the client has no file or a
different file shape). The client writes each leaf at its offset, then
verifies that its rebuilt root equals the authoritative root.

## Repository layout

```
merkle.go     package docs: model, protocol, efficiency guarantees
hash.go       Hash, Hasher
node.go       Node, Patch, Ref
index.go      Index interface
indexer.go    Indexer, NewIndexer, options
message.go    wire message types and payloads
codec.go      Link, Codec
sync.go       Source, Sink, Serve, Sync
errors.go     sentinel errors
```
