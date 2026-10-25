package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestExpandManyMatchesDotfiles(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "note.txt"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ExpandMany("*", work, work)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, filepath.Join(work, ".env")) {
		t.Fatalf("dotfile was skipped: %v", got)
	}
	if !slices.Contains(got, filepath.Join(work, "note.txt")) {
		t.Fatalf("note.txt missing: %v", got)
	}
}

func TestExpandManyRejectsParentEscape(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "proj")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := ExpandMany("../*", work, home)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestExpandManyDoesNotFollowDirectorySymlink(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := ExpandMany("link/*", work, work)
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("got %v, want ErrSymlink", err)
	}
	got, err := ExpandMany("*", work, work)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, secret) {
		t.Fatalf("listed a file outside the workdir: %v", got)
	}
}

func TestExpandManyRejectsSymlinkAncestor(t *testing.T) {
	outside := t.TempDir()
	nested := filepath.Join(outside, "nested")
	secret := filepath.Join(nested, "secret.txt")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	got, err := ExpandMany("link/nested/*", work, work)
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("got %v, paths %v; want ErrSymlink", err, got)
	}
	listed, err := ExpandMany("*/*", work, work)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(listed, secret) {
		t.Fatalf("listed a file through a symlink: %v", listed)
	}
}

func TestExpandManyAllowsFirmlinkPrefix(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "note.txt"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ExpandMany(filepath.Join(work, "*"), work, work)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, filepath.Join(work, "note.txt")) {
		t.Fatalf("firmlink prefix hid the workdir: %v", got)
	}
}

func TestExpandManyRequiresWorkDir(t *testing.T) {
	_, err := ExpandMany("*", "", "/Users/someone")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestExpandManyEmptyGlob(t *testing.T) {
	work := t.TempDir()
	got, err := ExpandMany("*.pem", work, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("invented a path for a glob with no match: %v", got)
	}
}
