package policy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
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

// ExpandMany resolves a pattern to paths inside its base directory.
// A glob that cleans outside that base, or walks a symlink to a different directory, is rejected.
func ExpandMany(pattern, workDir, home string) ([]string, error) {
	abs, err := Expand(pattern, workDir, home)
	if err != nil {
		return nil, err
	}
	base, err := patternBase(pattern, workDir, home)
	if err != nil {
		return nil, err
	}
	if base != "" && !within(base, abs) {
		return nil, fmt.Errorf("%w: pattern %q leaves %s", ErrInvalid, pattern, base)
	}
	if !hasMeta(abs) {
		return []string{abs}, nil
	}
	rootDir, parts := splitGlob(abs)
	if err := rejectEscapingSymlinks(base, rootDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	root, err := openRoot(rootDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	matches, err := matchFrom(root, "", parts)
	if err != nil {
		return nil, err
	}
	slices.Sort(matches)
	return matches, nil
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

func patternBase(pattern, workDir, home string) (string, error) {
	if _, ok := strings.CutPrefix(pattern, "~"); ok {
		if home == "" {
			return "", fmt.Errorf("%w: home directory is unknown", ErrInvalid)
		}
		return filepath.Clean(home), nil
	}
	if filepath.IsAbs(pattern) {
		return string(filepath.Separator), nil
	}
	if workDir == "" {
		return "", fmt.Errorf("%w: working directory is unknown", ErrInvalid)
	}
	return filepath.Clean(workDir), nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	if rel == ".." {
		return false
	}
	_, escaped := strings.CutPrefix(rel, ".."+string(filepath.Separator))
	return !escaped
}

func hasMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func splitGlob(abs string) (string, []string) {
	abs = filepath.Clean(abs)
	parts := strings.Split(strings.TrimPrefix(abs, string(filepath.Separator)), string(filepath.Separator))
	dir := string(filepath.Separator)
	for i, part := range parts {
		if hasMeta(part) {
			return dir, parts[i:]
		}
		dir = filepath.Join(dir, part)
	}
	return abs, nil
}

// openRoot opens dir with os.Open and refuses a symlink.
// Later lookups go through os.OpenRoot so a link cannot leave dir.
func openRoot(dir string) (*os.Root, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !opened.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrInvalid, dir)
	}
	linked, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, linked) {
		if linked.Mode()&os.ModeSymlink == 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, dir)
		}
		if err := rejectEscapingSymlink(dir); err != nil {
			return nil, err
		}
	}
	return os.OpenRoot(dir)
}

// rejectEscapingSymlinks walks each name from start to dir.
// A symlink is kept only when its target is the same path, as with /tmp and /private/tmp.
func rejectEscapingSymlinks(start, dir string) error {
	rel, err := filepath.Rel(start, dir)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s", ErrInvalid, dir)
	}
	if rel == "." {
		return rejectEscapingSymlink(start)
	}
	cur := start
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if err := rejectEscapingSymlink(cur); err != nil {
			return err
		}
	}
	return nil
}

func rejectEscapingSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if SameAlias(path, target) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrSymlink, path)
}

func matchFrom(root *os.Root, rel string, parts []string) ([]string, error) {
	if len(parts) == 0 {
		return []string{filepath.Join(root.Name(), filepath.FromSlash(rel))}, nil
	}
	head, rest := parts[0], parts[1:]
	if !hasMeta(head) {
		next := head
		if rel != "" {
			next = rel + "/" + head
		}
		full := filepath.Join(root.Name(), filepath.FromSlash(next))
		info, err := root.Lstat(next)
		if len(rest) == 0 {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return []string{full}, nil
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, full)
		}
		if !info.IsDir() {
			return nil, nil
		}
		return matchFrom(root, next, rest)
	}
	dir := "."
	if rel != "" {
		dir = rel
	}
	f, err := root.Open(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := f.ReadDir(-1)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if name == "." || name == ".." {
			continue
		}
		ok, err := filepath.Match(head, name)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
		}
		if !ok {
			continue
		}
		next := name
		if rel != "" {
			next = rel + "/" + name
		}
		full := filepath.Join(root.Name(), filepath.FromSlash(next))
		info, err := root.Lstat(next)
		if err != nil {
			return nil, err
		}
		if len(rest) == 0 {
			out = append(out, full)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		sub, err := matchFrom(root, next, rest)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	return out, nil
}
