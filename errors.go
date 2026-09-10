package merkle

import "errors"

// ErrMismatch is returned when a received chunk does not hash to its
// advertised hash, or when the synced file's root does not match the
// root the server announced.
var ErrMismatch = errors.New("merkle: hash mismatch")

// ErrProtocol is returned when a peer sends a malformed or unexpected
// message.
var ErrProtocol = errors.New("merkle: protocol error")
