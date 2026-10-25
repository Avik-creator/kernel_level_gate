package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"kernel_level_gate/internal/policy"
)

func TestWriteAppendsLaunchAndBlock(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2026, 10, 25, 16, 30, 0, 0, time.UTC)
	launch := Event{
		Time:    when,
		Kind:    KindLaunch,
		Command: []string{"go", "test"},
		WorkDir: dir,
	}
	block := Event{
		Time:    when.Add(time.Second),
		Kind:    KindBlock,
		Command: []string{"curl", "https://example"},
		WorkDir: dir,
		Reason:  "curl",
	}
	if err := Write(dir, launch); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, block); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dirInfo.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []Event
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	if len(got) != 2 {
		t.Fatalf("events %d: %s", len(got), body)
	}
	if !got[0].Time.Equal(when) || got[0].Kind != KindLaunch || !slices.Equal(got[0].Command, launch.Command) {
		t.Fatalf("launch %+v", got[0])
	}
	if got[1].Kind != KindBlock || got[1].Reason != "curl" {
		t.Fatalf("block %+v", got[1])
	}
}

func TestWriteRejectsSymlinkAndBadKind(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "real.jsonl")
	if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, FileName)
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	err := Write(dir, Event{Time: time.Now(), Kind: KindLaunch, Command: []string{"go"}})
	if !errors.Is(err, policy.ErrSymlink) {
		t.Fatalf("symlink: got %v, want ErrSymlink", err)
	}
	body, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep\n" {
		t.Fatalf("followed the symlink and wrote %q", body)
	}
	if err := Write(t.TempDir(), Event{Kind: "eperm"}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("kind: got %v, want ErrInvalid", err)
	}
}

func TestWriteRejectsSymlinkDirAndHardLink(t *testing.T) {
	target := t.TempDir()
	parent := t.TempDir()
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := Write(link, Event{Time: time.Unix(1, 0).UTC(), Kind: KindLaunch, Command: []string{"go"}})
	if !errors.Is(err, policy.ErrSymlink) {
		t.Fatalf("dir symlink: got %v, want ErrSymlink", err)
	}
	if _, err := os.Stat(filepath.Join(target, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created the log through the directory symlink")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
		t.Fatal(err)
	}
	err = Write(dir, Event{Time: time.Unix(2, 0).UTC(), Kind: KindLaunch, Command: []string{"go"}})
	if !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("hard link: got %v, want ErrInvalid", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep\n" {
		t.Fatalf("wrote through the hard link: %q", body)
	}
}

func TestWriteKeepsOneLineWhenFieldsContainNewlines(t *testing.T) {
	dir := t.TempDir()
	ev := Event{
		Time:    time.Unix(3, 0).UTC(),
		Kind:    KindBlock,
		Command: []string{"echo", "a\nb"},
		Reason:  "line1\nline2",
	}
	if err := Write(dir, ev); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(body, []byte("\n")) != 1 {
		t.Fatalf("record broke into lines: %q", body)
	}
}

func TestWriteRejectsEmptyDir(t *testing.T) {
	err := Write("", Event{Time: time.Unix(4, 0).UTC(), Kind: KindLaunch})
	if !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}
