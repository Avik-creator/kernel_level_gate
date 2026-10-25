package enforce

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"kernel_level_gate/internal/policy"
)

func TestSeatbeltProfileOrder(t *testing.T) {
	plan := Plan{
		Home:          "/Users/me",
		WorkDir:       "/Users/me/proj",
		AllowDirs:     []string{"/Users/me/.cache"},
		AllowFiles:    []string{"/Users/me/.claude.json"},
		DenyDirs:      []string{"/Users/me/proj/secrets"},
		DenyFiles:     []string{"/Users/me/proj/.env"},
		ReadOnlyDirs:  []string{"/Users/me/proj/.ssh"},
		ReadOnlyFiles: []string{"/Users/me/proj/.bashrc"},
		Hide:          "/Users/me/.kgate",
		Exec:          []string{"/usr/bin/curl"},
		Network:       policy.NetworkOff,
	}
	argv, err := Seatbelt(plan, []string{"/bin/echo", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(argv[:3], []string{"sandbox-exec", "-p", argv[2]}) || argv[3] != "--" || !slices.Equal(argv[4:], []string{"/bin/echo", "hello"}) {
		t.Fatalf("argv %q", argv)
	}
	profile := argv[2]
	if strings.Contains(profile, "hello") {
		t.Fatal("command leaked into the profile")
	}
	var prev int
	for _, rule := range []string{
		"(version 1)",
		"(allow default)",
		"(deny file-write*)",
		`(deny file-read* (subpath "/Users/me"))`,
		`(deny file-write* (subpath "/Users/me"))`,
		`(allow file-read* file-write* (subpath "/Users/me/proj"))`,
		`(allow file-read* file-write* (subpath "/Users/me/.cache"))`,
		`(allow file-read* file-write* (literal "/Users/me/.claude.json"))`,
		`(deny file-write* (subpath "/Users/me/proj/.ssh"))`,
		`(deny file-write* (literal "/Users/me/proj/.bashrc"))`,
		`(deny file-read* (subpath "/Users/me/proj/secrets"))`,
		`(deny file-read* (literal "/Users/me/proj/.env"))`,
		`(deny file-read* file-write* (subpath "/Users/me/.kgate"))`,
		`(deny process-exec (literal "/usr/bin/curl"))`,
		"(deny network-outbound)",
		"(allow network-outbound (local ip))",
	} {
		at := strings.Index(profile, rule)
		if at < prev {
			t.Fatalf("%s is out of order in %s", rule, profile)
		}
		prev = at
	}
	if _, err := os.Lstat("/private/tmp"); err == nil && !strings.Contains(profile, `(allow file-write* (subpath "/private/tmp"))`) {
		t.Fatal("missing temp write allowance")
	}
}

func TestSeatbeltRejectsRestrictedAndBadPaths(t *testing.T) {
	plan := Plan{Home: "/Users/me", WorkDir: "/Users/me/proj", Network: policy.NetworkRestricted}
	_, err := Seatbelt(plan, []string{"/bin/true"})
	if !errors.Is(err, policy.ErrNetwork) {
		t.Fatalf("restricted: got %v", err)
	}
	plan.Network = policy.NetworkOpen
	argv, err := Seatbelt(plan, []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(argv[2], "network-outbound") {
		t.Fatalf("open profile restricted the network: %s", argv[2])
	}
	plan.Network = policy.NetworkOff
	plan.WorkDir = "/Users/me/proj\"x"
	_, err = Seatbelt(plan, []string{"/bin/true"})
	if !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("quote: got %v", err)
	}
	if _, err := Seatbelt(plan, nil); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("empty command: got %v", err)
	}
}

func TestSeatbeltRunsOnThisMac(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip(err)
	}
	home := t.TempDir()
	work := filepath.Join(home, "proj")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "note"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "secret"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(policy.Config{Network: policy.NetworkOff}, work, home, filepath.Join(home, ".kgate"))
	if err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(plan.WorkDir, "note")
	if out, err := runSeatbelt(plan, "/bin/cat", note); err != nil || string(out) != "hello" {
		t.Fatalf("read work: %v %q", err, out)
	}
	made := filepath.Join(plan.WorkDir, "made")
	if _, err := runSeatbelt(plan, "/usr/bin/touch", made); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(plan.Home, "secret")
	if _, err := runSeatbelt(plan, "/bin/cat", secret); err == nil {
		t.Fatal("home file was readable")
	}
	outside := filepath.Join(plan.Home, "nope")
	if _, err := runSeatbelt(plan, "/usr/bin/touch", outside); err == nil {
		t.Fatal("home file was writable")
	}
}

func runSeatbelt(plan Plan, command ...string) ([]byte, error) {
	argv, err := Seatbelt(plan, command)
	if err != nil {
		return nil, err
	}
	return exec.Command(argv[0], argv[1:]...).CombinedOutput()
}
