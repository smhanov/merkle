package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestRemoteSyntax (AC5): an all-digits tail after the last colon is a
// TCP port even with a user@ prefix; user@host:path parses to an ssh
// remote with that path; a bare user@host without a path is a clear
// error.
func TestRemoteSyntax(t *testing.T) {
	dir := t.TempDir()
	served := filepath.Join(dir, "served.txt")
	writeChunkedFile(t, served, 200000, 7) // 4 chunks of 64 KiB
	port := startServe(t, served)

	t.Run("tcp host:port", func(t *testing.T) {
		p1 := filepath.Join(dir, "p1.txt")
		out, errOut, exit := runMerkle(t, dir, "127.0.0.1:"+strconv.Itoa(port), "p1.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if out != "" && !strings.Contains(out, "bytes transferred") {
			t.Fatalf("want a transfer line, got: %q", out)
		}
		assertFilesEqual(t, served, p1)
	})

	t.Run("tcp user@host:port", func(t *testing.T) {
		p2 := filepath.Join(dir, "p2.txt")
		out, errOut, exit := runMerkle(t, dir, "smhanov@127.0.0.1:"+strconv.Itoa(port), "p2.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if out != "" && !strings.Contains(out, "bytes transferred") {
			t.Fatalf("want a transfer line, got: %q", out)
		}
		assertFilesEqual(t, served, p2)
	})

	t.Run("parse ssh remote", func(t *testing.T) {
		sp, err := parseSpec("smhanov@megos:/path/to/file")
		if err != nil {
			t.Fatalf("parseSpec: %v", err)
		}
		if sp.kind != kindSSH {
			t.Fatalf("kind = %d, want kindSSH", sp.kind)
		}
		if sp.host != "megos" || sp.path != "/path/to/file" {
			t.Fatalf("host = %q, path = %q; want megos, /path/to/file", sp.host, sp.path)
		}
	})

	t.Run("bare user@host", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "smhanov@megos", "somelocal.txt")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if !strings.Contains(errOut, "missing path") {
			t.Fatalf("want \"missing path\" in stderr, got: %q", errOut)
		}
	})
}

// TestPushOverTCP (AC3): pushing over an explicit TCP port to a
// running serve updates the served file: fresh into an empty file,
// unchanged re-run, one-chunk delta.
func TestPushOverTCP(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "local.txt")
	writeChunkedFile(t, local, 200000, 7) // 4 chunks of 64 KiB
	served := filepath.Join(dir, "served.txt")
	if err := os.WriteFile(served, nil, 0644); err != nil {
		t.Fatalf("write empty %s: %v", served, err)
	}
	remote := "127.0.0.1:" + strconv.Itoa(startServe(t, served))

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "local.txt", remote)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"local.txt -> 127.0.0.1:", "bytes transferred"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, local, served)
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "local.txt", remote)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "up to date") {
			t.Fatalf("want up-to-date line, got: %q", out)
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, local, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "local.txt", remote)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "bytes transferred") {
			t.Fatalf("want \"bytes transferred\" in output, got: %q", out)
		}
		if n := reportedBytes(t, out); n >= 65536+2048 {
			t.Fatalf("delta transfer %d bytes is not less than one chunk + overhead", n)
		}
		assertFilesEqual(t, local, served)
	})
}

// TestPullOverTCP (AC4): pulling over an explicit TCP port from a
// running serve; the serve re-indexes its file per connection, so an
// edit of the served file on disk is picked up by a re-pull without a
// serve restart.
func TestPullOverTCP(t *testing.T) {
	dir := t.TempDir()
	served := filepath.Join(dir, "served.txt")
	writeChunkedFile(t, served, 200000, 7) // 4 chunks of 64 KiB
	remote := "127.0.0.1:" + strconv.Itoa(startServe(t, served))
	local := filepath.Join(dir, "local.txt") // absent: fresh fetch

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, remote, "local.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"-> local.txt:", "4 of 4 chunks changed"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, served, local)
	})

	t.Run("edit on disk then re-pull", func(t *testing.T) {
		flipByte(t, served, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, remote, "local.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "1 of 4 chunks changed") {
			t.Fatalf("want \"1 of 4 chunks changed\" in output, got: %q", out)
		}
		assertFilesEqual(t, served, local)
	})
}

// TestSSHPush (AC7): push over loopback ssh — the remote runs
// `merkle serve <path> -listen -`, whose per-connection line is
// forwarded to the local process's stderr.
func TestSSHPush(t *testing.T) {
	if !sshOK {
		t.Skip("loopback ssh unavailable")
	}
	t.Parallel()
	dir := t.TempDir()
	local := filepath.Join(dir, "local.txt")
	writeChunkedFile(t, local, 200000, 7) // 4 chunks of 64 KiB
	remote := filepath.Join(dir, "remote-push.txt")
	if err := os.WriteFile(remote, nil, 0644); err != nil {
		t.Fatalf("write empty %s: %v", remote, err)
	}
	remoteSpec := "127.0.0.1:" + remote

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "local.txt", remoteSpec)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"local.txt -> 127.0.0.1:", "bytes transferred"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, local, remote)
		if !strings.Contains(errOut, "stdio -> ") {
			t.Fatalf("want the remote \"stdio -> \" line in local stderr, got: %q", errOut)
		}
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "local.txt", remoteSpec)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "up to date") {
			t.Fatalf("want up-to-date line, got: %q", out)
		}
		if !strings.Contains(errOut, "up to date") {
			t.Fatalf("want the remote \"up to date\" line in local stderr, got: %q", errOut)
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, local, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "local.txt", remoteSpec)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if n := reportedBytes(t, out); n >= 65536+2048 {
			t.Fatalf("delta transfer %d bytes is not less than one chunk + overhead", n)
		}
		assertFilesEqual(t, local, remote)
		if !strings.Contains(errOut, "1 of 4 chunks changed") {
			t.Fatalf("want the remote \"1 of 4 chunks changed\" line in local stderr, got: %q", errOut)
		}
	})
}

// TestSSHPull (AC7): pull over loopback ssh — the local file is the
// updated side, so the changed-chunk clause is on the local stdout.
func TestSSHPull(t *testing.T) {
	if !sshOK {
		t.Skip("loopback ssh unavailable")
	}
	t.Parallel()
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote-src.txt")
	writeChunkedFile(t, remote, 200000, 7) // 4 chunks of 64 KiB
	remoteSpec := "127.0.0.1:" + remote
	local := filepath.Join(dir, "local-pull.txt") // absent: fresh fetch

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, remoteSpec, "local-pull.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"-> local-pull.txt:", "4 of 4 chunks changed"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		assertFilesEqual(t, remote, local)
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, remoteSpec, "local-pull.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "up to date") {
			t.Fatalf("want up-to-date line, got: %q", out)
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, remote, 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, remoteSpec, "local-pull.txt")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if !strings.Contains(out, "1 of 4 chunks changed") {
			t.Fatalf("want \"1 of 4 chunks changed\" in output, got: %q", out)
		}
		assertFilesEqual(t, remote, local)
	})
}
