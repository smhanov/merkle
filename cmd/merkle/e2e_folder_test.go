package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mustMkdir creates path (and any missing parents) or fails the test.
func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func TestFolderLocal(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	mustMkdir(t, filepath.Join(src, "sub"))
	writeChunkedFile(t, filepath.Join(src, "a.txt"), 200000, 7)
	writeChunkedFile(t, filepath.Join(src, "sub/b.txt"), 1000, 8)
	// dst starts absent: a local mirror must create it (and sub/) itself.

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src", "dst")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"a.txt:", "sub/b.txt:", "2 files synced", "bytes transferred"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
		if strings.Contains(out, "up to date") {
			t.Fatalf("unexpected \"up to date\" in fresh output: %q", out)
		}
		assertFilesEqual(t, filepath.Join(src, "a.txt"), filepath.Join(dst, "a.txt"))
		assertFilesEqual(t, filepath.Join(src, "sub/b.txt"), filepath.Join(dst, "sub/b.txt"))
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src", "dst")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"a.txt: up to date", "sub/b.txt: up to date", "2 files synced"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, filepath.Join(src, "a.txt"), 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "src", "dst")
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if strings.Contains(out, "a.txt: up to date") {
			t.Fatalf("changed file reported up to date: %q", out)
		}
		if !strings.Contains(out, "sub/b.txt: up to date") {
			t.Fatalf("want unchanged file up to date, got: %q", out)
		}
		assertFilesEqual(t, filepath.Join(src, "a.txt"), filepath.Join(dst, "a.txt"))
		assertFilesEqual(t, filepath.Join(src, "sub/b.txt"), filepath.Join(dst, "sub/b.txt"))
	})
}

func TestFolderPushTCP(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	remote := filepath.Join(dir, "remote")
	mustMkdir(t, filepath.Join(src, "sub"))
	writeChunkedFile(t, filepath.Join(src, "a.txt"), 200000, 7)
	writeChunkedFile(t, filepath.Join(src, "sub/b.txt"), 1000, 8)
	mustMkdir(t, remote)

	port := startServe(t, remote)
	end := "127.0.0.1:" + strconv.Itoa(port)

	t.Run("fresh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src", end)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		assertFilesEqual(t, filepath.Join(src, "a.txt"), filepath.Join(remote, "a.txt"))
		assertFilesEqual(t, filepath.Join(src, "sub/b.txt"), filepath.Join(remote, "sub/b.txt"))
		if !strings.Contains(out, "2 files synced") {
			t.Fatalf("want summary line, got: %q", out)
		}
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src", end)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"a.txt: up to date", "sub/b.txt: up to date"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
	})

	t.Run("delta", func(t *testing.T) {
		flipByte(t, filepath.Join(src, "a.txt"), 100000) // inside chunk 1
		out, errOut, exit := runMerkle(t, dir, "src", end)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		if strings.Contains(out, "a.txt: up to date") {
			t.Fatalf("changed file reported up to date: %q", out)
		}
		assertFilesEqual(t, filepath.Join(src, "a.txt"), filepath.Join(remote, "a.txt"))
		assertFilesEqual(t, filepath.Join(src, "sub/b.txt"), filepath.Join(remote, "sub/b.txt"))
	})
}

func TestFolderPushSSH(t *testing.T) {
	if !sshOK {
		t.Skip("loopback ssh unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	remote := filepath.Join(dir, "remote")
	mustMkdir(t, filepath.Join(src, "sub"))
	writeChunkedFile(t, filepath.Join(src, "a.txt"), 200000, 7)
	writeChunkedFile(t, filepath.Join(src, "sub/b.txt"), 1000, 8)
	mustMkdir(t, remote)

	remoteSpec := "127.0.0.1:" + remote // non-digit tail: an ssh remote

	t.Run("fresh", func(t *testing.T) {
		_, errOut, exit := runMerkle(t, dir, "src", remoteSpec)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		assertFilesEqual(t, filepath.Join(src, "a.txt"), filepath.Join(remote, "a.txt"))
		assertFilesEqual(t, filepath.Join(src, "sub/b.txt"), filepath.Join(remote, "sub/b.txt"))
		for _, want := range []string{"stdio -> a.txt:", "stdio -> sub/b.txt:"} {
			if !strings.Contains(errOut, want) {
				t.Fatalf("want %q in stderr, got: %q", want, errOut)
			}
		}
	})

	t.Run("no-op", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "src", remoteSpec)
		if exit != 0 {
			t.Fatalf("exit %d, stderr: %q", exit, errOut)
		}
		for _, want := range []string{"a.txt: up to date", "sub/b.txt: up to date"} {
			if !strings.Contains(out, want) {
				t.Fatalf("want %q in output, got: %q", want, out)
			}
		}
	})
}

func TestFolderPullRemoteErr(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	mustMkdir(t, dst)

	t.Run("tcp", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "127.0.0.1:9999", "dst")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if !strings.Contains(errOut, "not supported") {
			t.Fatalf("want \"not supported\" in stderr, got: %q", errOut)
		}
	})

	t.Run("ssh", func(t *testing.T) {
		out, errOut, exit := runMerkle(t, dir, "127.0.0.1:"+dst, "dst")
		if exit == 0 {
			t.Fatalf("exit 0, out: %q", out)
		}
		if !strings.Contains(errOut, "not supported") {
			t.Fatalf("want \"not supported\" in stderr, got: %q", errOut)
		}
	})
}

func TestFolderTraversalGuard(t *testing.T) {
	got, err := resolveDirPath("/data/root", "a/b.txt")
	if err != nil || got != "/data/root/a/b.txt" {
		t.Fatalf("resolveDirPath(/data/root, a/b.txt) = (%q, %v), want (/data/root/a/b.txt, nil)", got, err)
	}
	for _, rel := range []string{"../x", "a/../../y", ".."} {
		if _, err := resolveDirPath("/data/root", rel); err == nil {
			t.Fatalf("resolveDirPath(/data/root, %s) succeeded, want an error", rel)
		}
	}
}

func TestFolderSortedOrder(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	mustMkdir(t, filepath.Join(src, "m"))
	writeChunkedFile(t, filepath.Join(src, "z.txt"), 100, 1)
	writeChunkedFile(t, filepath.Join(src, "a.txt"), 100, 2)
	writeChunkedFile(t, filepath.Join(src, "m/c.txt"), 100, 3)
	mustMkdir(t, dst)

	out, errOut, exit := runMerkle(t, dir, "src", "dst")
	if exit != 0 {
		t.Fatalf("exit %d, stderr: %q", exit, errOut)
	}
	ia := strings.Index(out, "a.txt:")
	im := strings.Index(out, "m/c.txt:")
	iz := strings.Index(out, "z.txt:")
	if ia < 0 || im < 0 || iz < 0 {
		t.Fatalf("missing per-file lines (ia=%d im=%d iz=%d): %q", ia, im, iz, out)
	}
	if !(ia < im && im < iz) {
		t.Fatalf("per-file lines not in sorted relpath order (ia=%d im=%d iz=%d): %q", ia, im, iz, out)
	}
}

func TestFolderFailureAndSkip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	mustMkdir(t, src)
	writeChunkedFile(t, filepath.Join(src, "good1.txt"), 100, 1)
	writeChunkedFile(t, filepath.Join(src, "good2.txt"), 100, 2)
	writeChunkedFile(t, filepath.Join(src, "bad.txt"), 100, 3)
	if err := os.Chmod(filepath.Join(src, "bad.txt"), 0); err != nil {
		t.Fatalf("chmod bad.txt: %v", err)
	}
	if err := os.Symlink("good1.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Fatalf("symlink link.txt: %v", err)
	}
	mustMkdir(t, dst)

	out, errOut, exit := runMerkle(t, dir, "src", "dst")
	if exit == 0 {
		t.Fatalf("exit 0, out: %q", out)
	}
	if !strings.Contains(errOut, "bad.txt:") {
		t.Fatalf("want the failed file in stderr, got: %q", errOut)
	}
	if !strings.Contains(errOut, "link.txt: skipped") {
		t.Fatalf("want the skipped symlink in stderr, got: %q", errOut)
	}
	for _, want := range []string{"good1.txt:", "good2.txt:", "2 files synced", ", 1 skipped", ", 1 failed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("want %q in output, got: %q", want, out)
		}
	}
	if strings.Contains(out, "bad.txt:") {
		t.Fatalf("failed file in the success lines: %q", out)
	}
	assertFilesEqual(t, filepath.Join(src, "good1.txt"), filepath.Join(dst, "good1.txt"))
	assertFilesEqual(t, filepath.Join(src, "good2.txt"), filepath.Join(dst, "good2.txt"))
	if _, err := os.Stat(filepath.Join(dst, "link.txt")); err == nil {
		t.Fatalf("dst/link.txt exists, want the skipped symlink not copied")
	}
}
