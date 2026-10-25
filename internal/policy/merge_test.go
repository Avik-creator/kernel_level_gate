package policy

import (
	"errors"
	"slices"
	"testing"
)

func testConfig() Config {
	return Config{
		Network:      NetworkRestricted,
		AllowNet:     []string{"api.github.com", "proxy.golang.org"},
		AllowedPaths: []string{"~/.cache", "src"},
		DenyRead:     []string{".env", "*.pem"},
		DenyExec:     []string{"curl"},
		MaskStdout: MaskStdout{
			Presets:  []string{"openai"},
			Patterns: []MaskPattern{{Regex: `token=\S+`}},
		},
	}
}

func TestMergeKeepsAbsentKeys(t *testing.T) {
	base := testConfig()
	got, err := Merge(base, Overlay{}, "/Users/me")
	if err != nil {
		t.Fatal(err)
	}
	if got.Network != NetworkRestricted {
		t.Fatalf("network %q", got.Network)
	}
	if !slices.Equal(got.DenyRead, []string{".env", "*.pem"}) {
		t.Fatalf("deny_read %v", got.DenyRead)
	}
	got.DenyRead[0] = "changed"
	if base.DenyRead[0] != ".env" {
		t.Fatal("merge aliased the base deny list")
	}
}

func TestMergeNetworkCanOnlyTighten(t *testing.T) {
	got, err := Merge(testConfig(), Overlay{Network: new(NetworkOff)}, "/Users/me")
	if err != nil {
		t.Fatal(err)
	}
	if got.Network != NetworkOff {
		t.Fatalf("network %q", got.Network)
	}

	_, err = Merge(testConfig(), Overlay{Network: new(NetworkOpen)}, "/Users/me")
	if !errors.Is(err, ErrWiden) {
		t.Fatalf("got %v, want ErrWiden", err)
	}

	bad := Network("sometimes")
	_, err = Merge(testConfig(), Overlay{Network: &bad}, "/Users/me")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestMergeAllowListsOnlyShrink(t *testing.T) {
	home := "/Users/me"
	over := Overlay{
		AllowNet:     new([]string{"API.GitHub.com", "api.github.com"}),
		AllowedPaths: new([]string{"/Users/me/.cache"}),
	}
	got, err := Merge(testConfig(), over, home)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AllowNet, []string{"api.github.com"}) {
		t.Fatalf("allow_net %v", got.AllowNet)
	}
	if !slices.Equal(got.AllowedPaths, []string{"/Users/me/.cache"}) {
		t.Fatalf("allowed_paths %v", got.AllowedPaths)
	}

	_, err = Merge(testConfig(), Overlay{AllowNet: new([]string{"example.com"})}, home)
	if !errors.Is(err, ErrWiden) {
		t.Fatalf("host: got %v, want ErrWiden", err)
	}
	_, err = Merge(testConfig(), Overlay{AllowedPaths: new([]string{"/tmp/other"})}, home)
	if !errors.Is(err, ErrWiden) {
		t.Fatalf("path: got %v, want ErrWiden", err)
	}

	got, err = Merge(testConfig(), Overlay{AllowNet: new([]string{})}, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowNet) != 0 {
		t.Fatalf("empty allow_net left %v", got.AllowNet)
	}
}

func TestMergeUnionsDeniesAndMasks(t *testing.T) {
	over := Overlay{
		DenyRead: new([]string{".env", "secrets"}),
		DenyExec: new([]string{"kubectl delete"}),
		MaskStdout: new(MaskStdout{
			Presets:  []string{"openai", "bearer"},
			Patterns: []MaskPattern{{Regex: `sk-[A-Za-z0-9]+`, ShowPrefix: 3}},
		}),
	}
	got, err := Merge(testConfig(), over, "/Users/me")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.DenyRead, []string{".env", "*.pem", "secrets"}) {
		t.Fatalf("deny_read %v", got.DenyRead)
	}
	if !slices.Equal(got.DenyExec, []string{"curl", "kubectl delete"}) {
		t.Fatalf("deny_exec %v", got.DenyExec)
	}
	if !slices.Equal(got.MaskStdout.Presets, []string{"openai", "bearer"}) {
		t.Fatalf("presets %v", got.MaskStdout.Presets)
	}
	if len(got.MaskStdout.Patterns) != 2 || got.MaskStdout.Patterns[1].ShowPrefix != 3 {
		t.Fatalf("patterns %+v", got.MaskStdout.Patterns)
	}

	_, err = Merge(testConfig(), Overlay{MaskStdout: new(MaskStdout{
		Patterns: []MaskPattern{{Regex: "("}},
	})}, "/Users/me")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("regex: got %v, want ErrInvalid", err)
	}
}

func TestWidenAddsOnlySessionAllows(t *testing.T) {
	home := "/Users/me"
	got, err := Widen(testConfig(), []string{"example.com"}, []string{"~/.config"}, home)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.AllowNet, "example.com") {
		t.Fatalf("allow_net %v", got.AllowNet)
	}
	if !slices.Contains(got.AllowedPaths, "/Users/me/.config") {
		t.Fatalf("allowed_paths %v", got.AllowedPaths)
	}
	if !slices.Equal(got.DenyRead, []string{".env", "*.pem"}) {
		t.Fatalf("widen changed deny_read %v", got.DenyRead)
	}

	_, err = Widen(Config{Network: NetworkOff}, []string{"example.com"}, nil, home)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("allow-net on off: got %v, want ErrInvalid", err)
	}
}
