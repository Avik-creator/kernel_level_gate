package enforce

import (
	"fmt"
	"os"
	"strings"

	"kernel_level_gate/internal/policy"
)

// writableRoots are write exceptions outside the working directory.
// They are applied before the home write denial so a temp root cannot reopen home.
var writableRoots = []string{"/private/tmp", "/private/var/tmp", "/private/var/folders", "/dev"}

// seatbeltHostLimit is the host filter sandbox-exec accepts.
const seatbeltHostLimit = "sandbox-exec: host must be * or localhost in network address"

// Seatbelt returns the sandbox-exec argv for plan.
// The command is argv, never text inside the profile.
func Seatbelt(plan Plan, command []string) ([]string, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("%w: command is empty", policy.ErrInvalid)
	}
	if err := seatbeltNetwork(plan.Network); err != nil {
		return nil, err
	}
	profile, err := seatbeltProfile(plan)
	if err != nil {
		return nil, err
	}
	return append([]string{"sandbox-exec", "-p", profile, "--"}, command...), nil
}

func seatbeltNetwork(network policy.Network) error {
	if !network.Valid() {
		return fmt.Errorf("%w: network %q", policy.ErrInvalid, network)
	}
	if network == policy.NetworkRestricted {
		return fmt.Errorf("%w: %s", policy.ErrNetwork, seatbeltHostLimit)
	}
	return nil
}

func seatbeltProfile(plan Plan) (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n(deny file-write*)\n")
	if err := writeRule(&b, "deny file-read*", "subpath", plan.Home); err != nil {
		return "", err
	}
	for _, path := range writableRoots {
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		if err := writeRule(&b, "allow file-write*", "subpath", path); err != nil {
			return "", err
		}
	}
	if err := writeRule(&b, "deny file-write*", "subpath", plan.Home); err != nil {
		return "", err
	}
	if err := writeRule(&b, "allow file-read* file-write*", "subpath", plan.WorkDir); err != nil {
		return "", err
	}
	if err := writePaths(&b, "allow file-read* file-write*", "subpath", plan.AllowDirs); err != nil {
		return "", err
	}
	if err := writePaths(&b, "allow file-read* file-write*", "literal", plan.AllowFiles); err != nil {
		return "", err
	}
	if err := writePaths(&b, "deny file-write*", "subpath", plan.ReadOnlyDirs); err != nil {
		return "", err
	}
	if err := writePaths(&b, "deny file-write*", "literal", plan.ReadOnlyFiles); err != nil {
		return "", err
	}
	if err := writePaths(&b, "deny file-read*", "subpath", plan.DenyDirs); err != nil {
		return "", err
	}
	if err := writePaths(&b, "deny file-read*", "literal", plan.DenyFiles); err != nil {
		return "", err
	}
	if plan.Hide != "" {
		if err := writeRule(&b, "deny file-read* file-write*", "subpath", plan.Hide); err != nil {
			return "", err
		}
	}
	if err := writePaths(&b, "deny process-exec", "literal", plan.Exec); err != nil {
		return "", err
	}
	if plan.Network == policy.NetworkOff {
		// (local ip) also matches a public address on this OS.
		b.WriteString("(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:*\"))\n")
	}
	return b.String(), nil
}

func writePaths(b *strings.Builder, action, kind string, paths []string) error {
	for _, path := range paths {
		if err := writeRule(b, action, kind, path); err != nil {
			return err
		}
	}
	return nil
}

func writeRule(b *strings.Builder, action, kind, path string) error {
	quoted, err := quotePath(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(b, "(%s (%s %s))\n", action, kind, quoted)
	return nil
}

func quotePath(path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\"\n\r") {
		return "", fmt.Errorf("%w: path %q", policy.ErrInvalid, path)
	}
	return `"` + path + `"`, nil
}
