package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/smhanov/merkle"
)

// remoteKind classifies a src/dst argument: a local path, a raw TCP
// endpoint (host:port) for loopback testing against a running serve, or
// an ssh remote [user@]host:path (design decisions 1 and 2 of
// .plans/T003-example-cli.md).
type remoteKind int

const (
	kindLocal remoteKind = iota
	kindTCP
	kindSSH
)

// spec is a parsed src/dst argument. kindTCP fills host and port;
// kindSSH fills user ("" for the current user), host, and path;
// kindLocal fills path.
type spec struct {
	kind remoteKind
	user string
	host string
	path string
	port int
}

// parseSpec classifies a src/dst argument per design decision 2 of
// .plans/T003-example-cli.md: a non-empty all-digits tail after the
// last ":" is a TCP port, even with a user@ prefix; otherwise an "@"
// makes the argument an ssh remote [user@]host:path, and a ":" without
// an "@" an ssh remote host:path, both with a mandatory path;
// otherwise the argument is a local path. Paths with colons need
// quoting or relative form (Linux).
func parseSpec(s string) (spec, error) {
	i := strings.LastIndex(s, ":")
	if i >= 0 && allDigits(s[i+1:]) {
		hostpart := s[:i]
		user, host := "", hostpart
		if j := strings.Index(hostpart, "@"); j >= 0 {
			user, host = hostpart[:j], hostpart[j+1:]
		}
		port, err := strconv.Atoi(s[i+1:])
		if err != nil || port > 65535 {
			return spec{}, fmt.Errorf("merkle: remote %s: port %s out of range 0..65535", s, s[i+1:])
		}
		return spec{kind: kindTCP, user: user, host: host, port: port}, nil
	}
	if strings.Contains(s, "@") {
		if i < 0 {
			return spec{}, fmt.Errorf("merkle: remote %s: missing path (want user@host:path)", s)
		}
		left, path := s[:i], s[i+1:]
		user, host := "", left
		if j := strings.Index(left, "@"); j >= 0 {
			user, host = left[:j], left[j+1:]
		}
		if path == "" {
			return spec{}, fmt.Errorf("merkle: remote %s: missing path (want user@host:path)", s)
		}
		return spec{kind: kindSSH, user: user, host: host, path: path}, nil
	}
	if i >= 0 {
		host, path := s[:i], s[i+1:]
		if path == "" {
			return spec{}, fmt.Errorf("merkle: remote %s: missing path (want host:path)", s)
		}
		return spec{kind: kindSSH, host: host, path: path}, nil
	}
	return spec{kind: kindLocal, path: s}, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// header is the CLI-level session header written on the channel before
// the merkle protocol, per design decision 1 of
// .plans/T003-example-cli.md: the role of this side (0 = client, its
// file gets updated; 1 = server, its file is the source) and a path
// slot that is empty in v1 and reserved for per-file directory mode.
type header struct {
	role byte
	path string
}

// writeHeader writes [role 1B][len(path) 2B big-endian][path bytes].
func writeHeader(w io.Writer, role byte, path string) error {
	var b [3]byte
	b[0] = role
	binary.BigEndian.PutUint16(b[1:], uint16(len(path)))
	if _, err := w.Write(b[:]); err != nil {
		return err
	}
	if path != "" {
		if _, err := w.Write([]byte(path)); err != nil {
			return err
		}
	}
	return nil
}

// readHeader reads a header written by writeHeader.
func readHeader(r io.Reader) (header, error) {
	var b [3]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return header{}, err
	}
	path := make([]byte, binary.BigEndian.Uint16(b[1:]))
	if _, err := io.ReadFull(r, path); err != nil {
		return header{}, err
	}
	return header{role: b[0], path: string(path)}, nil
}

// exchangeHeader writes own header and reads the peer's. Both sides
// always write first, so there is no ordering dependency.
func exchangeHeader(rw io.ReadWriter, role byte, path string) (header, error) {
	if err := writeHeader(rw, role, path); err != nil {
		return header{}, err
	}
	return readHeader(rw)
}

// countingRW wraps an io.ReadWriter and counts the bytes observed on
// it in both directions, for the per-connection transfer total.
type countingRW struct {
	rw io.ReadWriter
	n  int64
}

func (c *countingRW) Read(p []byte) (int, error) {
	n, err := c.rw.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingRW) Write(p []byte) (int, error) {
	n, err := c.rw.Write(p)
	c.n += int64(n)
	return n, err
}

// N returns the total bytes read plus written.
func (c *countingRW) N() int64 { return c.n }

// msgLeafWire is the wire type byte of the leaf message. The type
// constants are unexported in package merkle; per the wire format in
// README.md and protocol.go the types are hello=1, query=2, reply=3,
// ack=4, leaf=5.
const msgLeafWire byte = 5

// Session header role values (design decision 1).
const (
	roleClient   byte = 0 // this side's file gets updated (Pull)
	roleSource   byte = 1 // this side's file is the source (Serve)
	roleResident byte = 2 // resident: the peer's role decides this side
)

// frameTracker walks the wire framing (1-byte type, 4-byte big-endian
// length, payload) byte by byte so a type-valued byte inside a payload
// is never miscounted as a frame start, and counts the leaf frames
// seen.
type frameTracker struct {
	leaf   int64
	ph     int // 0 = type byte, 1 = length field, 2 = payload
	lenBuf uint32
	lenGot int
	skip   int // payload bytes left in the current frame
}

func (t *frameTracker) feed(b byte) {
	switch t.ph {
	case 0:
		if b == msgLeafWire {
			t.leaf++
		}
		t.ph, t.lenBuf, t.lenGot = 1, 0, 0
	case 1:
		t.lenBuf = t.lenBuf<<8 | uint32(b)
		t.lenGot++
		if t.lenGot == 4 {
			if t.lenBuf == 0 {
				t.ph = 0
			} else {
				t.ph, t.skip = 2, int(t.lenBuf)
			}
		}
	default:
		t.skip--
		if t.skip == 0 {
			t.ph = 0
		}
	}
}

// frameCounter passes the read side of a protocol channel through
// unchanged, counting leaf frames received, so the CLI can report
// changed-chunk counts without re-parsing protocol payloads.
type frameCounter struct {
	next io.Reader
	frameTracker
}

func (f *frameCounter) Read(p []byte) (int, error) {
	n, err := f.next.Read(p)
	for i := 0; i < n; i++ {
		f.feed(p[i])
	}
	return n, err
}

// frameCountingWriter is the write-side counterpart of frameCounter:
// it counts the leaf frames sent.
type frameCountingWriter struct {
	next io.Writer
	frameTracker
}

func (f *frameCountingWriter) Write(p []byte) (int, error) {
	n, err := f.next.Write(p)
	for i := 0; i < n; i++ {
		f.feed(p[i])
	}
	return n, err
}

// protocolRW runs the protocol phase of a session (after the session
// header) over an inner io.ReadWriter, counting leaf frames in each
// direction.
type protocolRW struct {
	fr *frameCounter
	fw *frameCountingWriter
}

func (p *protocolRW) Read(b []byte) (int, error)  { return p.fr.Read(b) }
func (p *protocolRW) Write(b []byte) (int, error) { return p.fw.Write(b) }

// sessionResult is the telemetry of one per-file session: the byte
// total on the channel (from the countingRW), leaf frames received
// (updated side) and sent (source side), and the local file size
// before and after the session.
type sessionResult struct {
	bytes     int64
	leavesIn  int64
	leavesOut int64
	preSize   int64
	postSize  int64
}

// syncFile runs one per-file sync session over rw, the atomic sync
// unit shared by every code path (plan step 3 of
// .plans/T003-example-cli.md); T007 will loop it per file with real
// paths. myRole: roleClient = the local file at path gets updated
// (Pull; absent file = fresh fetch), roleSource = the local file at
// path is the source (Serve; absent = error), roleResident = the
// peer's header decides (peer source -> updated side, peer client ->
// source side). Pass a *countingRW so res.bytes is the channel's
// byte total. It is a single-file session: syncFileRel with an empty
// relPath.
//
// Close contract: the local file is closed before returning in all
// cases. Pull returns the passed prior index (patched in place) or a
// fresh sentinel for an absent file, never a second live index, so
// the index is closed exactly once here; the sentinel's nil memo
// makes Close a no-op.
func syncFile(rw io.ReadWriter, myRole byte, path string) (res sessionResult, err error) {
	return syncFileRel(rw, myRole, path, "")
}

// syncFileRel is the per-file sync unit with a relPath carried in the
// session header: exchange the header (myRole, relPath), resolve the
// effective role, and run the file I/O core.
func syncFileRel(rw io.ReadWriter, myRole byte, path, relPath string) (res sessionResult, err error) {
	peer, err := exchangeHeader(rw, myRole, relPath)
	if err != nil {
		return res, err
	}
	role := myRole
	if myRole == roleResident {
		role = roleFromPeer(peer)
	}
	return runFile(rw, role, path)
}

// roleFromPeer resolves this side's role when resident: the peer's
// role decides (peer source -> updated side, peer client -> source
// side).
func roleFromPeer(peer header) byte {
	if peer.role == roleSource {
		return roleClient
	}
	return roleSource
}

// runFile is the file I/O core of a per-file session: set up the
// protocol channel over rw, open path, and run merkle.Pull (updated
// side) or merkle.Serve (source side), filling res.
func runFile(rw io.ReadWriter, role byte, path string) (res sessionResult, err error) {
	prw := &protocolRW{
		fr: &frameCounter{next: rw},
		fw: &frameCountingWriter{next: rw},
	}

	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	var prior, got *merkle.Index
	defer func() {
		if got != nil {
			got.Close()
		}
		if prior != nil && prior != got {
			prior.Close()
		}
	}()

	if role == roleClient {
		// Updated side.
		fi, statErr := os.Stat(path)
		switch {
		case statErr == nil:
			if fi.IsDir() {
				return res, fmt.Errorf("merkle: %s: is a directory", path)
			}
			f, err = os.OpenFile(path, os.O_RDWR, 0644)
			if err != nil {
				return res, err
			}
			res.preSize = fi.Size()
			prior, err = merkle.NewIndex(f, fi.Size())
			if err != nil {
				return res, err
			}
		case os.IsNotExist(statErr):
			// Absent file: fresh fetch, create it.
			f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return res, err
			}
		default:
			return res, statErr
		}
		got, err = merkle.Pull(prw, f, prior)
		if err != nil {
			return res, err
		}
		fi, err := f.Stat()
		if err != nil {
			return res, err
		}
		res.postSize = fi.Size()
	} else {
		// Source side.
		f, err = os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return res, fmt.Errorf("merkle: %s: no such file", path)
			}
			return res, err
		}
		fi, statErr := f.Stat()
		if statErr != nil {
			return res, statErr
		}
		if fi.IsDir() {
			return res, fmt.Errorf("merkle: %s: is a directory", path)
		}
		ix, statErr := merkle.NewIndex(f, fi.Size())
		if statErr != nil {
			return res, statErr
		}
		got = ix
		err = merkle.Serve(prw, ix)
		res.preSize = fi.Size()
		res.postSize = fi.Size()
	}

	res.leavesIn = prw.fr.leaf
	res.leavesOut = prw.fw.leaf
	if c, ok := rw.(*countingRW); ok {
		res.bytes = c.N()
	}
	return res, err
}

// sshRW pairs the stdin and stdout pipes of an ssh process into one
// io.ReadWriter: the session header and the protocol run on it,
// exactly the pipe rsync rides on (design decision 3).
type sshRW struct {
	r io.Reader
	w io.Writer
}

func (s *sshRW) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *sshRW) Write(p []byte) (int, error) { return s.w.Write(p) }

// sshSession starts `ssh [user@]host <remoteCmd>` and returns an
// io.ReadWriter over its stdio plus a finish function that closes
// the stdin pipe (EOF to the remote) and waits for the process,
// returning its exit error. The process's stderr is os.Stderr, so
// remote diagnostics and the remote serve's per-connection line
// surface locally (design decisions 3 and 6).
func sshSession(user, host, remoteCmd string) (io.ReadWriter, func() error, error) {
	target := host
	if user != "" {
		target = user + "@" + host
	}
	cmd := exec.Command("ssh", target, remoteCmd)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return &sshRW{r: stdout, w: stdin}, func() error {
		stdin.Close()
		err := cmd.Wait()
		if err == nil {
			return nil
		}
		return fmt.Errorf("ssh %s: %v", target, err)
	}, nil
}

// shellQuote single-quotes s for a remote login shell; embedded
// single quotes are escaped in the standard shell form
// (quote, backslash-quote, quote, quote).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// chunkCount is the number of 64 KiB chunks a size-byte file spans.
func chunkCount(size int64) int64 {
	if size <= 0 {
		return 0
	}
	return (size + 65535) / 65536
}

// oneShotLine formats the one-shot output line (decision 6): "up to
// date" when noop, else the byte total plus, when k > 0 (the updated
// file is local to the process), the changed-chunk clause.
func oneShotLine(src, dst string, n, m, k int64, noop bool) string {
	if noop {
		return src + " -> " + dst + ": up to date"
	}
	if k > 0 {
		return fmt.Sprintf("%s -> %s: %d bytes transferred (%d of %d chunks changed)", src, dst, n, m, k)
	}
	return fmt.Sprintf("%s -> %s: %d bytes transferred", src, dst, n)
}

// reportUpdatedSide prints the one-shot line for a session whose
// updated file is local (pull over TCP/ssh, and the dst side of a
// local-local sync): the changed-chunk clause comes from the updated
// side's telemetry, N from its byte total.
func reportUpdatedSide(res sessionResult, src, dst string) {
	noop := res.leavesIn == 0 && res.preSize == res.postSize
	fmt.Println(oneShotLine(src, dst, res.bytes, res.leavesIn, chunkCount(res.postSize), noop))
}

// reportPush prints the one-shot line for a remote push: the remote
// file's chunk count is unknown to this process, so only N is
// reported (decision 6).
func reportPush(res sessionResult, src, dst string) {
	fmt.Println(oneShotLine(src, dst, res.bytes, 0, 0, res.leavesOut == 0))
}

// serveLine formats the resident's per-connection line (decision 6):
// the updated side carries the changed-chunk clause (M = leaf frames
// received, K = the post-size chunk count); the source side reports the
// byte total only; a no-op session reports "up to date" in either role.
func serveLine(peer, name string, res sessionResult, wasUpdated bool) string {
	if wasUpdated {
		if res.leavesIn == 0 && res.preSize == res.postSize {
			return peer + " -> " + name + ": up to date"
		}
		return fmt.Sprintf("%s -> %s: %d bytes transferred (%d of %d chunks changed)", peer, name, res.bytes, res.leavesIn, chunkCount(res.postSize))
	}
	if res.leavesOut == 0 {
		return peer + " -> " + name + ": up to date"
	}
	return fmt.Sprintf("%s -> %s: %d bytes transferred", peer, name, res.bytes)
}

// wasUpdatedSide reports whether this side was the updated side of the
// session: it received leaf frames or its file size changed. The source
// side never receives leaf frames and its file never changes size, so
// the role is recoverable from the result alone.
func wasUpdatedSide(res sessionResult) bool {
	return res.leavesIn > 0 || res.preSize != res.postSize
}

// fail prints err with the "merkle: " prefix (added once) to stderr
// and exits 1 (decision 7).
func fail(err error) {
	if strings.HasPrefix(err.Error(), "merkle: ") {
		fmt.Fprintln(os.Stderr, err)
	} else {
		fmt.Fprintln(os.Stderr, "merkle: "+err.Error())
	}
	os.Exit(1)
}

// oneShotLocal mirrors src into dst over a 127.0.0.1 loopback
// connection: the dst side (updated side) runs in a goroutine on the
// accepted end, the src side on the dialed end of the same
// connection; the report comes from the dst side's perspective. If
// either side fails, the conn is closed so the peer unblocks instead
// of waiting for protocol messages that will never come.
func oneShotLocal(srcArg, dstArg string, src, dst spec) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		fail(err)
	}
	peer, err := ln.Accept()
	ln.Close()
	if err != nil {
		conn.Close()
		fail(err)
	}
	defer conn.Close()

	dstRW := &countingRW{rw: peer}
	srcRW := &countingRW{rw: conn}

	var (
		res      sessionResult
		mu       sync.Mutex
		firstErr error
	)
	setFirst := func(e error) {
		if e == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = e
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r, e := syncFile(dstRW, roleClient, dst.path)
		res = r
		setFirst(e)
		if e != nil {
			conn.Close() // unblock the peer
		}
	}()
	_, serr := syncFile(srcRW, roleSource, src.path)
	setFirst(serr)
	if serr != nil {
		conn.Close() // unblock the peer
	}
	<-done
	if firstErr != nil {
		fail(firstErr)
	}
	reportUpdatedSide(res, srcArg, dstArg)
}

// oneShotTCP dials a running merkle serve on the remote's host:port
// (loopback testing) and runs one session over it: roleSource pushes
// the local src, roleClient pulls into the local dst.
func oneShotTCP(srcArg, dstArg string, src, dst spec, role byte) {
	var end spec
	var localPath string
	if src.kind == kindTCP {
		end, localPath = src, dst.path
	} else {
		end, localPath = dst, src.path
	}
	conn, err := net.Dial("tcp", net.JoinHostPort(end.host, strconv.Itoa(end.port)))
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	res, err := syncFile(&countingRW{rw: conn}, role, localPath)
	if err != nil {
		fail(err)
	}
	if role == roleSource {
		reportPush(res, srcArg, dstArg)
	} else {
		reportUpdatedSide(res, srcArg, dstArg)
	}
}

// oneShotSSH shells out to `ssh [user@]host "merkle serve <path>
// -listen -"` and runs one session over the ssh stdio (design
// decision 3): roleSource pushes the local src to the remote path,
// roleClient pulls the remote path into the local dst.
func oneShotSSH(srcArg, dstArg string, src, dst spec, role byte) {
	var end spec
	var remotePath, localPath string
	if src.kind == kindSSH {
		end, remotePath, localPath = src, src.path, dst.path
	} else {
		end, remotePath, localPath = dst, dst.path, src.path
	}
	rw, finish, err := sshSession(end.user, end.host, "merkle serve "+shellQuote(remotePath)+" -listen -")
	if err != nil {
		fail(err)
	}
	res, err := syncFile(&countingRW{rw: rw}, role, localPath)
	ferr := finish()
	if err != nil {
		fail(err)
	}
	if ferr != nil {
		fail(ferr)
	}
	if role == roleSource {
		reportPush(res, srcArg, dstArg)
	} else {
		reportUpdatedSide(res, srcArg, dstArg)
	}
}

// walkDir collects the relpaths of every regular file under root and
// the relpaths of every skipped entry (symlinks and other non-regular,
// non-dir entries; counted, not followed), both sorted for
// determinism; the root dir itself is ignored.
func walkDir(root string) (files, skipped []string, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		switch {
		case d.Type().IsRegular():
			files = append(files, rel)
		case !d.IsDir():
			skipped = append(skipped, rel)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(files)
	sort.Strings(skipped)
	return files, skipped, nil
}

// perFileLine formats the per-file folder-sync line (relpath as
// subject, decision-6 shapes): "up to date" when the session was a
// no-op (updater side: no leaves received and size unchanged; source
// side: no leaves sent), else the byte total plus, for the updater
// side, the changed-chunk clause.
func perFileLine(rel string, res sessionResult, isUpdater bool) string {
	noop := false
	if isUpdater {
		noop = res.leavesIn == 0 && res.preSize == res.postSize
	} else {
		noop = res.leavesOut == 0
	}
	if noop {
		return rel + ": up to date"
	}
	if isUpdater {
		return fmt.Sprintf("%s: %d bytes transferred (%d of %d chunks changed)", rel, res.bytes, res.leavesIn, chunkCount(res.postSize))
	}
	return fmt.Sprintf("%s: %d bytes transferred", rel, res.bytes)
}

// reportFolderResult prints the skipped-file lines to stderr and the
// AC8 summary line to stdout, and exits 1 when any file failed (AC7).
func reportFolderResult(files, skipped []string, ok int, total int64, failed int) {
	for _, rel := range skipped {
		fmt.Fprintf(os.Stderr, "%s: skipped (not a regular file)\n", rel)
	}
	line := fmt.Sprintf("%d files synced, %d bytes transferred", ok, total)
	if len(skipped) > 0 {
		line += fmt.Sprintf(", %d skipped", len(skipped))
	}
	if failed > 0 {
		line += fmt.Sprintf(", %d failed", failed)
	}
	fmt.Println(line)
	if failed > 0 {
		os.Exit(1)
	}
}

// folderLocal mirrors srcDir into dstDir over a single 127.0.0.1
// loopback connection: per sorted file, the dst side runs as
// roleClient on the accepted end and the src side as roleSource on
// the dialed end of the same connection; the per-file line is the
// dst/updater side's. Parent dirs are created as needed; a failed
// file is reported to stderr and the connection dropped so the next
// file reconnects fresh (AC7).
func folderLocal(srcDir, dstDir string) {
	files, skipped, err := walkDir(srcDir)
	if err != nil {
		fail(err)
	}
	var (
		conn  net.Conn
		srcRW *countingRW
		dstRW *countingRW
	)
	open := func() error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		conn, err = net.Dial("tcp", ln.Addr().String())
		if err != nil {
			ln.Close()
			return err
		}
		peer, err := ln.Accept()
		ln.Close()
		if err != nil {
			conn.Close()
			return err
		}
		dstRW = &countingRW{rw: peer}
		srcRW = &countingRW{rw: conn}
		return nil
	}
	close := func() {
		if conn != nil {
			conn.Close()
		}
		conn, srcRW, dstRW = nil, nil, nil
	}
	defer close()

	var (
		ok     int
		total  int64
		failed int
	)
	for _, rel := range files {
		if dstRW == nil {
			if err := open(); err != nil {
				fail(err)
			}
		}
		srcPath := filepath.Join(srcDir, rel)
		dstPath := filepath.Join(dstDir, rel)
		os.MkdirAll(filepath.Dir(dstPath), 0o755)
		drw := dstRW
		var (
			dres sessionResult
			derr error
		)
		done := make(chan struct{}, 1)
		go func() {
			dres, derr = syncFileRel(drw, roleClient, dstPath, rel)
			if derr != nil {
				conn.Close() // unblock the peer
			}
			done <- struct{}{}
		}()
		_, serr := syncFileRel(srcRW, roleSource, srcPath, rel)
		if serr != nil {
			conn.Close() // unblock the peer
		}
		<-done
		switch {
		case derr != nil:
			fmt.Fprintf(os.Stderr, "%s: %v\n", rel, derr)
			failed++
			close()
		case serr != nil:
			fmt.Fprintf(os.Stderr, "%s: %v\n", rel, serr)
			failed++
			close()
		default:
			fmt.Println(perFileLine(rel, dres, true))
			total += dres.bytes
			ok++
		}
	}
	reportFolderResult(files, skipped, ok, total, failed)
}

// folderPush pushes the files of srcDir, in sorted relpath order, to a
// running `merkle serve <dir>` endpoint (step 2): TCP re-dials the
// endpoint per connection, ssh runs one `merkle serve <dir> -listen -`
// session per file over the ssh stdio (the remote exits after each).
// The per-file line is the source side's (byte total only); a failed
// file is reported to stderr and the connection dropped so the next
// file reconnects fresh (AC7).
func folderPush(srcDir string, end spec) {
	files, skipped, err := walkDir(srcDir)
	if err != nil {
		fail(err)
	}
	var (
		conn   net.Conn
		crw    *countingRW
		finish func() error
	)
	open := func() error {
		if end.kind == kindTCP {
			var err error
			conn, err = net.Dial("tcp", net.JoinHostPort(end.host, strconv.Itoa(end.port)))
			if err != nil {
				return err
			}
			crw = &countingRW{rw: conn}
			return nil
		}
		var rw io.ReadWriter
		var err error
		rw, finish, err = sshSession(end.user, end.host, "merkle serve "+shellQuote(end.path)+" -listen -")
		if err != nil {
			return err
		}
		crw = &countingRW{rw: rw}
		return nil
	}
	close := func() {
		if conn != nil {
			conn.Close()
		}
		if finish != nil {
			finish()
			finish = nil
		}
		conn, crw = nil, nil
	}
	defer close()

	var (
		ok     int
		total  int64
		failed int
	)
	for _, rel := range files {
		if crw == nil {
			if err := open(); err != nil {
				fail(err)
			}
		}
		res, err := syncFileRel(crw, roleSource, filepath.Join(srcDir, rel), rel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", rel, err)
			failed++
			close()
			continue
		}
		fmt.Println(perFileLine(rel, res, false))
		total += res.bytes
		ok++
	}
	reportFolderResult(files, skipped, ok, total, failed)
}

// handleServeConn runs one per-file session on a resident connection:
// syncFile re-opens and re-indexes the file, so a file edited on disk
// between connections is picked up without a restart and no file
// handle is kept across connections. A per-connection error is
// reported to stderr and the conn closed; the resident keeps
// accepting (decision 7).
func handleServeConn(conn net.Conn, name string) {
	peer := conn.RemoteAddr().String()
	defer conn.Close()
	res, err := syncFile(&countingRW{rw: conn}, roleResident, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s -> %s: %v\n", peer, name, err)
		return
	}
	fmt.Println(serveLine(peer, name, res, wasUpdatedSide(res)))
}

// resolveDirPath resolves a peer relpath against the served directory
// root and rejects any path that escapes it (the AC5 traversal guard).
func resolveDirPath(root, rel string) (string, error) {
	cleanRoot := filepath.Clean(root)
	full := filepath.Clean(filepath.Join(cleanRoot, rel))
	if full != cleanRoot && !strings.HasPrefix(full, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("merkle: path %q escapes the served directory", rel)
	}
	return full, nil
}

// serveDirFile runs one per-file session on a directory-resident
// connection: the peer's header carries the relpath of the file to
// sync (a directory has no single path of its own); parent
// directories are created as needed.
func serveDirFile(rw io.ReadWriter, root string) (res sessionResult, rel string, err error) {
	peer, err := exchangeHeader(rw, roleResident, "")
	if err != nil {
		return res, "", err
	}
	rel = peer.path
	if rel == "" {
		return res, "", fmt.Errorf("merkle: missing path (want <relpath>)")
	}
	path, err := resolveDirPath(root, rel)
	if err != nil {
		return res, rel, err
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	res, err = runFile(rw, roleFromPeer(peer), path)
	return res, rel, err
}

// isCleanClose reports whether err is the peer ending the connection
// (EOF, a reset, or a closed-network error) — the end of a folder
// rather than a fault worth logging.
func isCleanClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection reset by peer") || strings.Contains(s, "use of closed network connection")
}

// handleServeDirConn runs the per-file sessions of one folder on a
// resident directory connection, keyed by the relpath in each session
// header, until the client closes it. A per-connection error is
// reported to stderr and the conn closed; the resident keeps
// accepting (decision 7).
func handleServeDirConn(conn net.Conn, root string) {
	peer := conn.RemoteAddr().String()
	defer conn.Close()
	crw := &countingRW{rw: conn}
	for {
		res, rel, err := serveDirFile(crw, root)
		if err != nil {
			if !isCleanClose(err) {
				fmt.Fprintf(os.Stderr, "%s -> %s: %v\n", peer, root, err)
			}
			return // client closed (or errored): drop this conn, the accept loop takes the next
		}
		fmt.Println(serveLine(peer, rel, res, wasUpdatedSide(res)))
	}
}

// serveCmd implements `merkle serve <file-or-dir> [-listen addr]` (plan
// step 5): the resident sync endpoint for one file or one directory
// (directory: the peer's header carries each file's relpath). `-listen
// -` runs one session (file) or the folder's per-file sessions until
// stdin closes (directory) on stdin/stdout (the form an ssh one-shot
// runs on the remote, human output on stderr so the protocol stream
// stays clean); any other address runs a TCP accept loop. The
// path is checked at startup (decision 5) and re-opened per
// connection, never held.
func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":9000", "address to listen on; \"-\" = one session on stdin/stdout")
	file := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:] // file first: flag.Parse would stop there
	}
	fs.Parse(args)
	switch {
	case file == "" && fs.NArg() == 1: // flags before the file
		file = fs.Arg(0)
	case file != "" && fs.NArg() == 0:
	default:
		fmt.Fprintln(os.Stderr, "usage: merkle serve <file-or-dir> [-listen addr]")
		os.Exit(1)
	}
	name := file
	fi, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			fail(fmt.Errorf("merkle: %s: no such file", name))
		}
		fail(err)
	}
	isDir := fi.IsDir()
	if *listen == "-" {
		crw := &countingRW{rw: &sshRW{r: os.Stdin, w: os.Stdout}}
		if isDir {
			for {
				res, rel, err := serveDirFile(crw, name)
				if err != nil {
					if !isCleanClose(err) {
						fmt.Fprintf(os.Stderr, "stdio -> %s: %v\n", name, err)
					}
					return // stdin closed: the folder is done
				}
				fmt.Fprintln(os.Stderr, serveLine("stdio", rel, res, wasUpdatedSide(res)))
			}
		}
		res, err := syncFile(crw, roleResident, name)
		if err != nil {
			fail(err)
		}
		fmt.Fprintln(os.Stderr, serveLine("stdio", name, res, wasUpdatedSide(res)))
		return
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail(err)
	}
	fmt.Printf("serving %s at %s\n", name, ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fail(err)
		}
		if isDir {
			handleServeDirConn(conn, name)
		} else {
			handleServeConn(conn, name)
		}
	}
}

// isLocalDir reports whether p exists and is a directory (the folder
// dispatch test for a local src/dst argument).
func isLocalDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serveCmd(os.Args[2:])
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: merkle <src> <dst>")
		os.Exit(1)
	}
	srcArg, dstArg := os.Args[1], os.Args[2]
	src, err := parseSpec(srcArg)
	if err != nil {
		fail(err)
	}
	dst, err := parseSpec(dstArg)
	if err != nil {
		fail(err)
	}
	srcIsDir := src.kind == kindLocal && isLocalDir(src.path)
	dstIsDir := dst.kind == kindLocal && isLocalDir(dst.path)
	switch {
	case src.kind != kindLocal && dst.kind != kindLocal:
		fail(fmt.Errorf("v1 takes at most one remote endpoint"))
	case srcIsDir:
		if dst.kind == kindLocal {
			// dst may be an existing dir or not exist yet (created as
			// needed); only an existing regular file is a mistake.
			if fi, err := os.Stat(dst.path); err == nil && !fi.IsDir() {
				fail(fmt.Errorf("merkle: src is a directory but dst %q is a file", dst.path))
			}
			folderLocal(src.path, dst.path)
		} else {
			folderPush(src.path, dst)
		}
	case dstIsDir:
		if src.kind == kindLocal {
			fail(fmt.Errorf("merkle: src %q is a file but dst is a directory", src.path))
		}
		fail(fmt.Errorf("merkle: pulling a remote folder (%s) is not supported in v1", srcArg))
	case src.kind == kindLocal && dst.kind == kindLocal:
		oneShotLocal(srcArg, dstArg, src, dst)
	case dst.kind == kindTCP:
		oneShotTCP(srcArg, dstArg, src, dst, roleSource)
	case src.kind == kindTCP:
		oneShotTCP(srcArg, dstArg, src, dst, roleClient)
	case dst.kind == kindSSH:
		oneShotSSH(srcArg, dstArg, src, dst, roleSource)
	default: // src ssh, dst local
		oneShotSSH(srcArg, dstArg, src, dst, roleClient)
	}
}
