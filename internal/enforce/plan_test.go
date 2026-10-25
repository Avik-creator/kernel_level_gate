package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"kernel_level_gate/internal/policy"
)

func TestPrepareRefusesHomeAsWorkdir(t *testing.T) {
	home := t.TempDir()
	cfg := policy.Config{Network: policy.NetworkOff}
	_, err := Prepare(cfg, home, home, filepath.Join(home, ".kgate"))
	if !errors.Is(err, policy.ErrScope) {
		t.Fatalf("workdir is home: got %v, want ErrScope", err)
	}
	parent := t.TempDir()
	nested := filepath.Join(parent, "home")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = Prepare(cfg, parent, nested, filepath.Join(nested, ".kgate"))
	if !errors.Is(err, policy.ErrScope) {
		t.Fatalf("workdir contains home: got %v, want ErrScope", err)
	}
}

func TestPrepareCanonicalAllowAndDeny(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "proj")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(home, ".cache")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "out")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(work, "secret")
	alias := filepath.Join(work, "alias")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(home, ".kgate")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	curl := filepath.Join(work, "curl")
	if err := os.WriteFile(curl, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := policy.Config{
		Network:      policy.NetworkRestricted,
		AllowNet:     []string{"api.github.com"},
		AllowedPaths: []string{cache, filepath.Join(work, "missing"), configDir, filepath.Join(work, "out")},
		DenyRead:     []string{".env", "secrets", "secret"},
		DenyExec:     []string{"curl", "kubectl delete"},
	}
	_, err := Prepare(cfg, work, home, configDir)
	if !errors.Is(err, policy.ErrSymlink) {
		t.Fatalf("allow symlink: got %v, want ErrSymlink", err)
	}

	cfg.AllowedPaths = []string{cache, filepath.Join(work, "missing"), configDir}
	got, err := Prepare(cfg, work, home, configDir)
	if err != nil {
		t.Fatal(err)
	}
	workReal, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkDir != workReal {
		t.Fatalf("workdir %s", got.WorkDir)
	}
	if !slices.Contains(got.AllowDirs, mustReal(t, cache)) {
		t.Fatalf("allow %v", got.AllowDirs)
	}
	if slices.Contains(got.AllowDirs, mustReal(t, configDir)) || slices.Contains(got.AllowFiles, mustReal(t, configDir)) {
		t.Fatal("config dir was allowed")
	}
	if got.Hide != mustReal(t, configDir) {
		t.Fatalf("hide %s", got.Hide)
	}
	if !slices.Contains(got.DenyFiles, mustReal(t, filepath.Join(work, ".env"))) {
		t.Fatalf("deny files %v", got.DenyFiles)
	}
	if !slices.Contains(got.DenyFiles, mustReal(t, alias)) {
		t.Fatalf("hard link was not denied: %v", got.DenyFiles)
	}
	if !slices.Contains(got.DenyDirs, mustReal(t, filepath.Join(work, "secrets"))) {
		t.Fatalf("deny dirs %v", got.DenyDirs)
	}
	if !slices.Contains(got.ReadOnlyDirs, mustReal(t, filepath.Join(work, ".ssh"))) {
		t.Fatalf("readonly dirs %v", got.ReadOnlyDirs)
	}
	if !slices.Contains(got.Exec, mustReal(t, curl)) {
		t.Fatalf("exec %v", got.Exec)
	}
	if slices.Contains(got.Exec, "kubectl") {
		t.Fatal("subcommand was treated as a binary path")
	}
	if got.Network != policy.NetworkRestricted || !slices.Equal(got.AllowNet, []string{"api.github.com"}) {
		t.Fatalf("network %+v", got)
	}
}

func TestPrepareExecKeepsSymlinkEnds(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "proj")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	target := filepath.Join(bin, "curl-real")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "curl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	cfg := policy.Config{Network: policy.NetworkOff, DenyExec: []string{"curl", "kubectl delete"}}
	got, err := Prepare(cfg, work, home, filepath.Join(home, ".kgate"))
	if err != nil {
		t.Fatal(err)
	}
	linkReal := filepath.Join(mustReal(t, bin), "curl")
	if !slices.Contains(got.Exec, linkReal) || !slices.Contains(got.Exec, mustReal(t, target)) {
		t.Fatalf("exec %v", got.Exec)
	}
	if slices.Contains(got.Exec, "kubectl") {
		t.Fatal("subcommand was treated as a binary path")
	}
}

func TestPrepareSensitiveSymlinkAndAllowedHardlink(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "proj")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	ssh := filepath.Join(work, ".ssh")
	if err := os.Symlink(outside, ssh); err != nil {
		t.Fatal(err)
	}
	bashrc := filepath.Join(work, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(work, "secret")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "alias")
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{
		Network:      policy.NetworkOff,
		AllowedPaths: []string{alias},
		DenyRead:     []string{"secret"},
	}
	got, err := Prepare(cfg, work, home, filepath.Join(home, ".kgate"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.ReadOnlyFiles, filepath.Join(got.WorkDir, ".ssh")) {
		t.Fatalf("readonly files %v", got.ReadOnlyFiles)
	}
	if slices.Contains(got.ReadOnlyDirs, ssh) {
		t.Fatal("symlink was classified as a directory")
	}
	if !slices.Contains(got.ReadOnlyFiles, mustReal(t, bashrc)) {
		t.Fatalf("readonly files %v", got.ReadOnlyFiles)
	}
	aliasReal := mustReal(t, alias)
	if !slices.Contains(got.DenyFiles, aliasReal) {
		t.Fatalf("allowed hard link was not denied: %v", got.DenyFiles)
	}
	if slices.Contains(got.AllowFiles, aliasReal) || slices.Contains(got.AllowDirs, aliasReal) {
		t.Fatal("hard link stayed allowed")
	}
}

func mustReal(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}
