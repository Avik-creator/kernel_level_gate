package policy

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Expand resolves ~, absolute paths, and workdir-relative paths to a cleaned path.
func Expand(pattern, workDir, home string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalid)
	}
	if rest, ok := strings.CutPrefix(pattern, "~"); ok {
		if home == "" {
			return "", fmt.Errorf("%w: home directory is unknown", ErrInvalid)
		}
		if rest == "" {
			return filepath.Clean(home), nil
		}
		if rel, ok := strings.CutPrefix(rest, "/"); ok {
			return filepath.Clean(filepath.Join(home, rel)), nil
		}
		return "", fmt.Errorf("%w: unsupported path %q", ErrInvalid, pattern)
	}
	if filepath.IsAbs(pattern) || workDir == "" {
		return filepath.Clean(pattern), nil
	}
	return filepath.Clean(filepath.Join(workDir, pattern)), nil
}

// PatternKey is the identity used when two allow-list entries are compared.
// Relative patterns stay relative, so a project file cannot widen by rewriting
// a relative rule as a different absolute path.
func PatternKey(pattern, home string) (string, error) {
	if pattern == "~" || strings.HasPrefix(pattern, "~/") || filepath.IsAbs(pattern) {
		return Expand(pattern, "", home)
	}
	return filepath.Clean(pattern), nil
}

// AppleAlias strips the macOS /private firmlink prefix.
// /tmp and /private/tmp are the same path. A symlink to another directory is not.
func AppleAlias(path string) string {
	path = filepath.Clean(path)
	if rest, ok := strings.CutPrefix(path, "/private/"); ok {
		return "/" + rest
	}
	return path
}

// SameAlias reports whether two paths match after firmlink normalization.
func SameAlias(a, b string) bool {
	return AppleAlias(a) == AppleAlias(b)
}

// NormHost canonicalizes an allow_net entry for comparison and for quoting
// into the Linux network script.
func NormHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if err := ValidateHost(host); err != nil {
		return "", err
	}
	return host, nil
}

// ValidateHost accepts a DNS name or an IP address.
// Quotes, spaces, and shell metacharacters are rejected.
func ValidateHost(host string) error {
	if host == "" || len(host) > 253 {
		return fmt.Errorf("%w: host %q", ErrInvalid, host)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("%w: host %q", ErrInvalid, host)
	}
	for label := range strings.SplitSeq(host, ".") {
		if err := validLabel(host, label); err != nil {
			return err
		}
	}
	return nil
}

func validLabel(host, label string) error {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("%w: host %q", ErrInvalid, host)
	}
	for _, c := range label {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return fmt.Errorf("%w: host %q", ErrInvalid, host)
		}
	}
	return nil
}
