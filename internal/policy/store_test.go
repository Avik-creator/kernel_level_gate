package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := Default()
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network != want.Network || !slices.Equal(got.AllowNet, want.AllowNet) || !slices.Equal(got.DenyRead, want.DenyRead) {
		t.Fatalf("round trip %+v", got)
	}
	if !got.MaskStdout.Patterns[0].CaseInsensitive {
		t.Fatal("mask flag was dropped")
	}
	file := filepath.Join(dir, "config.yaml")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dirInfo.Mode().Perm())
	}
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(text), "# kgate global policy.") {
		t.Fatalf("missing header: %s", text)
	}
}

func TestLoadRejectsUnknownFieldAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("network: off\nextra: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: got %v, want ErrInvalid", err)
	}

	outside := filepath.Join(t.TempDir(), "real.yaml")
	if err := os.WriteFile(outside, []byte("network: open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrSymlink) {
		t.Fatalf("load symlink: got %v, want ErrSymlink", err)
	}
	if err := Save(dir, Default()); !errors.Is(err, ErrSymlink) {
		t.Fatalf("save symlink: got %v, want ErrSymlink", err)
	}
	body, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "network: open\n" {
		t.Fatalf("save followed the symlink and wrote %q", body)
	}
}

func TestLoadProjectOverlay(t *testing.T) {
	missing, err := LoadProject(filepath.Join(t.TempDir(), ".kgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if missing != (Overlay{}) {
		t.Fatalf("missing project file returned %+v", missing)
	}

	path := filepath.Join(t.TempDir(), ".kgate.yaml")
	body := "network: off\nallow_net: []\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network == nil || *got.Network != NetworkOff {
		t.Fatalf("network %+v", got.Network)
	}
	if got.AllowNet == nil || len(*got.AllowNet) != 0 {
		t.Fatalf("allow_net %#v", got.AllowNet)
	}
	if got.DenyRead != nil {
		t.Fatal("absent deny_read was set")
	}
}

func TestRemoveGlobalRefusesSymlinkAndForeignDir(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, Default()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KGATE_CONFIG_DIR", "")
	if err := RemoveGlobal(dir); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign dir: got %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KGATE_CONFIG_DIR", dir)
	target := t.TempDir()
	kept := filepath.Join(target, "keep")
	if err := os.WriteFile(kept, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KGATE_CONFIG_DIR", link)
	if err := RemoveGlobal(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink dir: got %v, want ErrSymlink", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("symlink removal deleted the target: %v", err)
	}

	t.Setenv("KGATE_CONFIG_DIR", dir)
	if err := RemoveGlobal(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir still present: %v", err)
	}
}

func TestGlobalDirUsesEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KGATE_CONFIG_DIR", dir)
	got, err := GlobalDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("GlobalDir %q", got)
	}
	_, err = Load(dir)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("missing config: got %v, want ErrNotInitialized", err)
	}
}
