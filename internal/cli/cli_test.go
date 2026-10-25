package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitDoctorAndNetwork(t *testing.T) {
	setup(t)
	out, _, code := callAll(t, "doctor")
	if code == 0 || !strings.HasPrefix(out, "BLOCKED\n") || !strings.Contains(out, "not initialized") {
		t.Fatalf("doctor before init: code %d %q", code, out)
	}
	if code, _, stderr := call(t, "init"); code != 0 {
		t.Fatal(stderr)
	}
	if code, _, stderr := call(t, "init"); code == 0 {
		t.Fatalf("second init: %s", stderr)
	}
	out, _, code = callAll(t, "doctor")
	if code == 0 || !strings.HasPrefix(out, "BLOCKED\n") || !strings.Contains(out, "kgate network off") {
		t.Fatalf("restricted doctor: code %d %q", code, out)
	}
	if code, _, stderr := call(t, "network", "open"); code != 0 {
		t.Fatal(stderr)
	}
	out, _, code = callAll(t, "doctor")
	if code != 0 || !strings.HasPrefix(out, "DEGRADED\n") {
		t.Fatalf("open doctor: code %d %q", code, out)
	}
	if code, _, stderr := call(t, "network", "off"); code != 0 {
		t.Fatal(stderr)
	}
	out, _, code = callAll(t, "doctor")
	if code != 0 || !strings.HasPrefix(out, "READY\n") {
		t.Fatalf("off doctor: code %d %q", code, out)
	}
}

func TestRunLaunchBlockAndMask(t *testing.T) {
	setup(t)
	if code, _, stderr := call(t, "init"); code != 0 {
		t.Fatal(stderr)
	}
	if code, _, stderr := call(t, "network", "off"); code != 0 {
		t.Fatal(stderr)
	}
	out, stderr, code := callAll(t, "run", "/usr/bin/true")
	if code != 0 {
		t.Fatalf("true: %d %s %s", code, out, stderr)
	}
	log := readAudit(t)
	if !strings.Contains(log, `"kind":"launch"`) || !strings.Contains(log, "/usr/bin/true") {
		t.Fatalf("audit %s", log)
	}
	token := "Bearer abcdef.ghijkl"
	out, stderr, code = callAll(t, "run", "/bin/echo", token)
	if code != 0 {
		t.Fatalf("echo: %d %s %s", code, out, stderr)
	}
	if strings.Contains(out, token) || !strings.Contains(out, "***") {
		t.Fatalf("mask %q", out)
	}
	_, stderr, code = callAll(t, "run", "/bin/sh", "-c", "exit 3")
	if code != 3 {
		t.Fatalf("exit 3: got %d %s", code, stderr)
	}
	before := readAudit(t)
	_, stderr, code = callAll(t, "run", "/usr/bin/curl", "https://example.com")
	if code == 0 || !strings.Contains(stderr, "blocked") {
		t.Fatalf("curl: %d %s", code, stderr)
	}
	after := readAudit(t)
	if !strings.Contains(after[len(before):], `"kind":"block"`) {
		t.Fatalf("block audit %s", after)
	}
}

func TestProjectCanTightenNetwork(t *testing.T) {
	work := setup(t)
	if code, _, stderr := call(t, "init"); code != 0 {
		t.Fatal(stderr)
	}
	if err := os.WriteFile(filepath.Join(work, ".kgate.yaml"), []byte("network: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := callAll(t, "run", "/usr/bin/true")
	if code != 0 {
		t.Fatalf("project off: %d %s", code, stderr)
	}
}

func TestAllowDenyAndReset(t *testing.T) {
	setup(t)
	if code, _, stderr := call(t, "init"); code != 0 {
		t.Fatal(stderr)
	}
	if code, _, stderr := call(t, "deny", "net", "api.github.com"); code != 0 {
		t.Fatal(stderr)
	}
	if code, _, stderr := call(t, "allow", "net", "Example.COM"); code != 0 {
		t.Fatal(stderr)
	}
	out, _, code := callAll(t, "status")
	if code != 0 || strings.Contains(out, "api.github.com") || !strings.Contains(out, "example.com") {
		t.Fatalf("status %q", out)
	}
	if code, _, stderr := call(t, "deny", "read", ".hidden"); code != 0 {
		t.Fatal(stderr)
	}
	out, _, _ = callAll(t, "status")
	if !strings.Contains(out, ".hidden") {
		t.Fatalf("deny read %q", out)
	}
	if code, _, stderr := call(t, "reset"); code == 0 {
		t.Fatalf("reset without force: %s", stderr)
	}
	if code, _, stderr := call(t, "reset", "--force"); code != 0 {
		t.Fatal(stderr)
	}
	out, _, code = callAll(t, "doctor")
	if code == 0 || !strings.HasPrefix(out, "BLOCKED\n") || !strings.Contains(out, "not initialized") {
		t.Fatalf("after reset: code %d %q", code, out)
	}
}

func TestInfoFdGoesBeforeTheCommand(t *testing.T) {
	got, err := withInfoFd([]string{"bwrap", "--bind", "/work", "/work", "--", "/bin/echo", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bwrap", "--bind", "/work", "/work", "--info-fd", "3", "--", "/bin/echo", "hi"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q", got)
	}
}

func setup(t *testing.T) string {
	t.Helper()
	t.Setenv("KGATE_CONFIG_DIR", t.TempDir())
	work := t.TempDir()
	t.Chdir(work)
	return work
}

func call(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	out, errText, code := callAll(t, args...)
	return code, out, errText
}

func callAll(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errText bytes.Buffer
	code := Main(args, strings.NewReader(""), &out, &errText)
	return out.String(), errText.String(), code
}

func readAudit(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(os.Getenv("KGATE_CONFIG_DIR"), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
