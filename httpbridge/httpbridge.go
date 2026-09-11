// Package httpbridge runs a merkle sync inside an ordinary HTTP
// request/response, so a sync can run behind a proxy that only speaks
// HTTP. The server is a plain http.Handler; the client streams the
// session over the connection with chunked transfer in both directions.
//
// A sync is a bidirectional ping-pong — the client answers each query the
// server sends — so it cannot go through http.Client, which buffers the
// request body before reading the response. The client therefore writes
// the chunked request body and reads the chunked response over the
// connection at the same time.
package httpbridge

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/smhanov/merkle"
)

// NewHandler returns an http.Handler that runs one Serve session per
// request against ix.
func NewHandler(ix *merkle.Index) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = merkle.Serve(&readWriter{r: r.Body, w: w}, ix)
	})
}

// Pull runs one Pull session as the HTTP client of url (http:// or
// https://), bringing dst up to date. prior is the current local index,
// or nil for an absent file.
func Pull(urlStr string, dst merkle.Sink, prior *merkle.Index) (*merkle.Index, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("httpbridge: url %q has no host", urlStr)
	}
	conn, err := dial(u)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	path := u.RequestURI()
	if _, err := fmt.Fprintf(conn,
		"POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
		path, u.Host); err != nil {
		return nil, err
	}
	return merkle.Pull(&readWriter{
		r: &respReader{br: bufio.NewReader(conn)},
		w: &chunkWriter{w: conn},
	}, dst, prior)
}

func dial(u *url.URL) (net.Conn, error) {
	switch u.Scheme {
	case "https":
		return tls.Dial("tcp", u.Host, &tls.Config{ServerName: u.Hostname()})
	case "http":
		return net.Dial("tcp", u.Host)
	default:
		return nil, fmt.Errorf("httpbridge: unsupported scheme %q", u.Scheme)
	}
}

// readWriter pairs a reader and a writer into the io.ReadWriter the sync
// runs over. A write is flushed when the writer is an http.Flusher, so
// each frame the server sends reaches the client immediately.
type readWriter struct {
	r io.Reader
	w io.Writer
}

func (x *readWriter) Read(p []byte) (int, error) { return x.r.Read(p) }
func (x *readWriter) Write(p []byte) (int, error) {
	n, err := x.w.Write(p)
	if f, ok := x.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

// chunkWriter frames each write as one chunked-transfer chunk.
type chunkWriter struct {
	w io.Writer
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if _, err := c.w.Write([]byte("\r\n")); err != nil {
		return n, err
	}
	return n, nil
}

// respReader decodes the chunked response body. On its first read it
// consumes the status line and headers, which only arrive once the
// server has read the client's first frame — so they cannot be read up
// front without deadlocking the session.
type respReader struct {
	br   *bufio.Reader
	rest []byte
	hdr  bool
}

func (c *respReader) Read(p []byte) (int, error) {
	if !c.hdr {
		if err := c.skipHeaders(); err != nil {
			return 0, err
		}
	}
	for len(c.rest) == 0 {
		size, err := readChunkSize(c.br)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			return 0, io.EOF
		}
		if size > 1<<20 {
			return 0, fmt.Errorf("httpbridge: chunk of %d bytes exceeds the frame cap", size)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(c.br, buf); err != nil {
			return 0, err
		}
		if _, err := c.br.ReadString('\n'); err != nil {
			return 0, err
		}
		c.rest = buf
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// skipHeaders reads and validates the status line, then discards the
// remaining header lines up to the blank line.
func (c *respReader) skipHeaders() error {
	line, err := readLine(c.br)
	if err != nil {
		return err
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) < 2 {
		return fmt.Errorf("httpbridge: bad status line %q", line)
	}
	if f[1] != "200" {
		return fmt.Errorf("httpbridge: unexpected status %s", line)
	}
	c.hdr = true
	for {
		line, err := readLine(c.br)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readChunkSize(r *bufio.Reader) (int64, error) {
	line, err := readLine(r)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(line), 16, 64)
}
