package enforce

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"kernel_level_gate/internal/policy"
)

func TestForOSRejectsAnUnknownKernel(t *testing.T) {
	if _, err := ForOS("windows"); !errors.Is(err, policy.ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestSeatbeltBuildArgs(t *testing.T) {
	box, err := ForOS("darwin")
	if err != nil {
		t.Fatal(err)
	}
	launch, err := box.BuildArgs(samplePlan(policy.NetworkOff), []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	defer launch.Close()
	if launch.Argv[0] != "sandbox-exec" || launch.Files != nil || launch.Slirp != nil {
		t.Fatalf("launch %+v", launch)
	}
	if _, err := box.BuildArgs(samplePlan(policy.NetworkRestricted), []string{"/bin/true"}); !errors.Is(err, policy.ErrNetwork) {
		t.Fatalf("restricted: got %v", err)
	}
}

func TestBwrapBuildArgsClosedNetwork(t *testing.T) {
	box, err := ForOS("linux")
	if err != nil {
		t.Fatal(err)
	}
	launch, err := box.BuildArgs(samplePlan(policy.NetworkOff), []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	defer launch.Close()
	if launch.Files != nil || launch.Slirp != nil || slices.Contains(launch.Argv, "--info-fd") {
		t.Fatalf("closed network %+v", launch)
	}
	if launch.Argv[0] != "bwrap" || !slices.Contains(launch.Argv, "--unshare-net") {
		t.Fatalf("argv %q", launch.Argv)
	}
}

func TestDoctorFollowsTheBackend(t *testing.T) {
	mac, err := ForOS("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		if got := mac.Doctor(policy.NetworkOff, nil); got.Word != "BLOCKED" || got.Code != 1 {
			t.Fatalf("missing sandbox-exec %+v", got)
		}
	} else {
		restricted := mac.Doctor(policy.NetworkRestricted, []string{"api.github.com"})
		if restricted.Code != 1 || !strings.Contains(restricted.Detail, "kgate network off") {
			t.Fatalf("restricted %+v", restricted)
		}
		if got := mac.Doctor(policy.NetworkOpen, nil); got.Word != "DEGRADED" || got.Code != 0 {
			t.Fatalf("open %+v", got)
		}
		if got := mac.Doctor(policy.NetworkOff, nil); got.Word != "READY" || got.Code != 0 {
			t.Fatalf("off %+v", got)
		}
	}

	linux, err := ForOS("linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		if got := linux.Doctor(policy.NetworkOff, nil); got.Word != "BLOCKED" || !strings.Contains(got.Detail, "bwrap") {
			t.Fatalf("missing bwrap %+v", got)
		}
		return
	}
	if got := linux.Doctor(policy.NetworkOpen, nil); got.Word != "DEGRADED" || got.Code != 0 {
		t.Fatalf("open %+v", got)
	}
	got := linux.Doctor(policy.NetworkRestricted, []string{"example.com"})
	_, slirpErr := exec.LookPath("slirp4netns")
	_, iptErr := exec.LookPath("iptables")
	if slirpErr != nil || iptErr != nil {
		if got.Word != "BLOCKED" || got.Code != 1 {
			t.Fatalf("missing net tool %+v", got)
		}
		return
	}
	if got.Word != "READY" || got.Code != 0 {
		t.Fatalf("restricted %+v", got)
	}
}

func TestBwrapBuildArgsRemovesTheTempDir(t *testing.T) {
	before := kgateTemps(t)
	box, err := ForOS("linux")
	if err != nil {
		t.Fatal(err)
	}
	plan := samplePlan(policy.NetworkOff)
	plan.Home = "relative"
	if _, err := box.BuildArgs(plan, []string{"/bin/true"}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if after := kgateTemps(t); after != before {
		t.Fatalf("temp dirs %d to %d", before, after)
	}
}

func kgateTemps(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "kgate-") {
			n++
		}
	}
	return n
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
	if _, err := withInfoFd([]string{"bwrap", "/bin/true"}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("missing --: got %v", err)
	}
}
