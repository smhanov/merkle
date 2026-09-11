package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// e2eBin is the absolute path of the binary TestMain built.
var e2eBin string

// sshOK reports whether loopback sshd with key auth works AND merkle
// is on the remote default PATH (the ssh tests skip when false).
var sshOK bool

func TestMain(m *testing.M) {
	_, thisFile, _, _ := runtime.Caller(0)
	buildDir := filepath.Dir(thisFile) // cmd/merkle

	dir, err := os.MkdirTemp("", "merkle-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, "merkle-e2e: temp dir:", err)
		os.Exit(1)
	}
	buildOut := &bytes.Buffer{}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "merkle"), ".")
	build.Dir = buildDir
	build.Stderr = buildOut
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "merkle-e2e: go build:", err)
		os.Stderr.Write(buildOut.Bytes())
		os.Exit(1)
	}
	e2eBin = filepath.Join(dir, "merkle")
	sshOK = probeSSH()

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// probeSSH runs `ssh -o BatchMode=yes -o ConnectTimeout=3 127.0.0.1
// command -v merkle` with a 5 s context timeout; true when it
// succeeds and prints a path.
func probeSSH() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
		"127.0.0.1", "command -v merkle").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// runMerkle runs the built binary with cwd dir and returns stdout,
// stderr, and the exit code; a 10 s deadline guards every call.
func runMerkle(t *testing.T, dir string, args ...string) (out, errOut string, exit int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e2eBin, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("merkle %v timed out after 10s", args)
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("run merkle %v: %v", args, err)
		}
	}
	return stdout.String(), stderr.String(), exit
}

// writeChunkedFile writes deterministic content (byte i = (i*31+seed)
// mod 256) so flipping one byte changes exactly one 64 KiB chunk hash.
func writeChunkedFile(t *testing.T, path string, size int, seed byte) {
	t.Helper()
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte((i*31 + int(seed)) & 0xFF)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func flipByte(t *testing.T, path string, off int) {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	buf[off] ^= 0x5A
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// startServe runs `merkle serve <file> -listen 127.0.0.1:0`, reads
// the "serving <name> at <addr>" startup line from stdout (10 s
// deadline), kills the process in t.Cleanup, and returns the real
// port.
func startServe(t *testing.T, file string) (port int) {
	t.Helper()
	cmd := exec.Command(e2eBin, "serve", file, "-listen", "127.0.0.1:0")
	cmd.Dir = filepath.Dir(file)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		_ = cmd.Wait()
	})
	lines := make(chan string, 1)
	lineErrs := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			lineErrs <- err
			return
		}
		lines <- line
	}()
	var line string
	select {
	case line = <-lines:
	case err := <-lineErrs:
		t.Fatalf("read serve startup line: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("merkle serve %s: no startup line after 10s", file)
	}
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "serving" {
		t.Fatalf("unexpected serve startup line: %q", line)
	}
	_, p, err := net.SplitHostPort(fields[len(fields)-1])
	if err != nil {
		t.Fatalf("parse serve address %q: %v", fields[len(fields)-1], err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		t.Fatalf("parse serve port %q: %v", p, err)
	}
	return port
}

// reportedBytes extracts N from a one-shot line
// "<src> -> <dst>: <N> bytes transferred ..." (T003 decision 6).
func reportedBytes(t *testing.T, line string) int64 {
	t.Helper()
	end := strings.Index(line, " bytes transferred")
	if end < 0 {
		t.Fatalf("no \"bytes transferred\" in %q", line)
	}
	start := strings.LastIndex(line[:end], ": ")
	if start < 0 {
		t.Fatalf("no \": \" before the transfer count in %q", line)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(line[start+2:end]), 10, 64)
	if err != nil {
		t.Fatalf("parse transfer count in %q: %v", line, err)
	}
	return n
}

func assertFilesEqual(t *testing.T, a, b string) {
	t.Helper()
	da, err := os.ReadFile(a)
	if err != nil {
		t.Fatalf("read %s: %v", a, err)
	}
	db, err := os.ReadFile(b)
	if err != nil {
		t.Fatalf("read %s: %v", b, err)
	}
	if !bytes.Equal(da, db) {
		t.Fatalf("%s (%d bytes) is not byte-equal to %s (%d bytes)", a, len(da), b, len(db))
	}
}

func TestLocalSync(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	writeChunkedFile(t, src, 200000, 7) // 4 chunks of 64 KiB

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src.txt", "dst.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{
			"src.txt -> dst.txt:",
			"bytes transferred",
			"4 of 4 chunks changed",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, src, dst)
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src.txt", "dst.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "src.txt -> dst.txt: up to date") {
			t.Fatalf("want up-to-date line, got: %q", out)
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, src, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "src.txt", "dst.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{
			"src.txt -> dst.txt:",
			"bytes transferred",
			"1 of 4 chunks changed",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		if n := reportedBytes(t, out); n >= 65536+2048 {
			t.Fatalf("delta transfer %d bytes is not less than one chunk + overhead", n)
		}
		assertFilesEqual(t, src, dst)
	})
}

// TestFileIntoDirectory pins `merkle <file> <dir>` (a local file whose
// destination is a directory): the file is copied into the directory
// under its own basename, like cp <file> <dir>/.
func TestFileIntoDirectory(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	if err := os.MkdirAll(filepath.Join(dir, "destdir"), 0755); err != nil {
		t.Fatalf("mkdir destdir: %v", err)
	}
	target := filepath.Join(dir, "destdir", "src.txt")
	writeChunkedFile(t, src, 200000, 7) // 4 chunks of 64 KiB

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src.txt", "destdir")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{
			"src.txt -> destdir/src.txt:",
			"bytes transferred",
			"4 of 4 chunks changed",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, src, target)
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src.txt", "destdir")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "src.txt -> destdir/src.txt: up to date") {
			t.Fatalf("want up-to-date line, got: %q", out)
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, src, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "src.txt", "destdir")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "1 of 4 chunks changed") {
			t.Fatalf("want 1-of-4 delta line, got: %q", out)
		}
		assertFilesEqual(t, src, target)
	})
}

func TestFailures(t *testing.T) {
	dir := t.TempDir()

	t.Run("closed port", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		writeChunkedFile(t, filepath.Join(dir, "a.txt"), 1000, 1)
		out, errOut, exit := runMerkle(t, dir, "a.txt", "127.0.0.1:"+strconv.Itoa(port))
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if errOut == "" {
			t.Fatalf("empty stderr")
		}
	})

	t.Run("missing local source", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "does-not-exist.txt", "b.txt")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if !strings.Contains(errOut, "no such file") {
			t.Fatalf("want \"no such file\" in stderr, got: %q", errOut)
		}
	})

	t.Run("serve of missing file", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "serve", "nope.txt", "-listen", "127.0.0.1:0")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if !strings.Contains(errOut, "no such file") {
			t.Fatalf("want \"no such file\" in stderr, got: %q", errOut)
		}
	})

	t.Run("ssh to absent remote file", func(t *testing.T) {
		if !sshOK {
			t.Skip("ssh unavailable")
		}
		writeChunkedFile(t, filepath.Join(dir, "a.txt"), 1000, 1)
		out, errOut, exit := runMerkle(t, dir, "a.txt", "127.0.0.1:"+dir+"/remote-absent.txt")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if errOut == "" {
			t.Fatalf("empty stderr")
		}
		// The remote serve's startup error should pass through over
		// ssh stderr; the hard gate is exit != 0 + non-empty stderr.
		if !strings.Contains(errOut, "no such file") {
			t.Logf("expected remote \"no such file\" in stderr, got: %q", errOut)
		}
	})
}
