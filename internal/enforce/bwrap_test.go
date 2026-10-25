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

func TestBubblewrapClosedNetwork(t *testing.T) {
	got, err := Bubblewrap(samplePlan(policy.NetworkOff), "", "", []string{"/bin/echo", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Script != "" || got.Slirp != nil {
		t.Fatalf("closed network returned slirp setup: %+v", got)
	}
	assertSeq(t, got.Argv, "--unshare-net")
	assertSeq(t, got.Argv, "--ro-bind", "/", "/")
	assertSeq(t, got.Argv, "--tmpfs", "/Users/me")
	assertSeq(t, got.Argv, "--bind", "/Users/me/proj", "/Users/me/proj")
	assertSeq(t, got.Argv, "--bind", "/Users/me/.cache", "/Users/me/.cache")
	assertSeq(t, got.Argv, "--bind", "/Users/me/.claude.json", "/Users/me/.claude.json")
	assertSeq(t, got.Argv, "--ro-bind", "/Users/me/proj/.ssh", "/Users/me/proj/.ssh")
	assertSeq(t, got.Argv, "--ro-bind", "/dev/null", "/Users/me/proj/.env")
	assertSeq(t, got.Argv, "--tmpfs", "/Users/me/proj/secrets")
	assertSeq(t, got.Argv, "--tmpfs", "/Users/me/.kgate")
	assertSeq(t, got.Argv, "--ro-bind", "/dev/null", "/usr/bin/curl")
	dash := slices.Index(got.Argv, "--")
	if dash < 0 || !slices.Equal(got.Argv[dash+1:], []string{"/bin/echo", "hello"}) {
		t.Fatalf("command %q", got.Argv)
	}
}

func TestBubblewrapOpenDoesNotUnshareNet(t *testing.T) {
	got, err := Bubblewrap(samplePlan(policy.NetworkOpen), "", "", []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got.Argv, "--unshare-net") {
		t.Fatalf("open network unshared: %q", got.Argv)
	}
}

func TestBubblewrapHostAllowListStaysOutOfTheScript(t *testing.T) {
	plan := samplePlan(policy.NetworkRestricted)
	plan.AllowNet = []string{"API.GitHub.com"}
	got, err := Bubblewrap(plan, "/tmp/kgate-net.sh", "/tmp/kgate-resolv.conf", []string{"/usr/bin/git", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Script, "git") || strings.Contains(got.Script, "status") || strings.Contains(got.Script, "github") {
		t.Fatal("script contains the command or the host")
	}
	if !strings.Contains(got.Script, `exec "$@"`) || !strings.Contains(got.Script, "10.0.2.100") {
		t.Fatal("script does not wait for slirp and exec the command")
	}
	for line := range strings.SplitSeq(got.Script, "\n") {
		if strings.Contains(line, "--dport 53") && !strings.Contains(line, "10.0.2.3") && !strings.Contains(line, "fd00::3") {
			t.Fatalf("port 53 is not limited to the slirp resolver: %s", line)
		}
	}
	if !strings.Contains(got.Script, "exit 125") || !strings.Contains(got.Script, "ip6tables") || !strings.Contains(got.Script, "disable_ipv6") {
		t.Fatal("script is missing the fail-closed checks")
	}
	if got.Resolv != "nameserver 10.0.2.3\n" {
		t.Fatalf("resolv %q", got.Resolv)
	}
	if !slices.Equal(got.Slirp, []string{"slirp4netns", "--configure", "--mtu=65520", "--disable-host-loopback"}) {
		t.Fatalf("slirp %q", got.Slirp)
	}
	assertSeq(t, got.Argv, "--ro-bind", "/tmp/kgate-resolv.conf", "/etc/resolv.conf")
	assertSeq(t, got.Argv, "--ro-bind", "/tmp/kgate-net.sh", "/tmp/kgate-net.sh")
	dash := slices.Index(got.Argv, "--")
	want := []string{"/bin/sh", "/tmp/kgate-net.sh", "api.github.com", "--", "/usr/bin/git", "status"}
	if dash < 0 || !slices.Equal(got.Argv[dash+1:], want) {
		t.Fatalf("argv tail %q", got.Argv[dash+1:])
	}
}

func TestBubblewrapMasksSensitiveSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(dir, ".ssh")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	plan := samplePlan(policy.NetworkOff)
	plan.ReadOnlyFiles = []string{link}
	got, err := Bubblewrap(plan, "", "", []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	assertSeq(t, got.Argv, "--ro-bind", "/dev/null", link)
}

func TestBubblewrapRejectsBadHostAndEmptyCommand(t *testing.T) {
	plan := samplePlan(policy.NetworkRestricted)
	plan.AllowNet = []string{"bad host"}
	_, err := Bubblewrap(plan, "/tmp/kgate-net.sh", "/tmp/kgate-resolv.conf", []string{"/bin/true"})
	if !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("host: got %v", err)
	}
	if _, err := Bubblewrap(samplePlan(policy.NetworkOff), "", "", nil); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("command: got %v", err)
	}
}

func TestLinuxNetTools(t *testing.T) {
	if err := LinuxNetTools(Plan{Network: policy.NetworkOff}); err != nil {
		t.Fatal(err)
	}
	_, slirpErr := exec.LookPath("slirp4netns")
	_, iptErr := exec.LookPath("iptables")
	err := LinuxNetTools(Plan{Network: policy.NetworkRestricted, AllowNet: []string{"example.com"}})
	if slirpErr != nil || iptErr != nil {
		if !errors.Is(err, policy.ErrNetwork) {
			t.Fatalf("missing tool: got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
}

func samplePlan(network policy.Network) Plan {
	return Plan{
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
		Network:       network,
	}
}

func assertSeq(t *testing.T, argv []string, want ...string) {
	t.Helper()
	for i := 0; i+len(want) <= len(argv); i++ {
		if slices.Equal(argv[i:i+len(want)], want) {
			return
		}
	}
	t.Fatalf("missing %q in %q", want, argv)
}
