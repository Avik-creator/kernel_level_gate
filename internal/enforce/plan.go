package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"kernel_level_gate/internal/policy"
)

// sensitive names are read-only when they already sit inside an exposed directory.
var sensitive = []string{
	".ssh", ".gnupg", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".gitconfig",
}

// Plan is the resolved policy a sandbox backend enforces.
type Plan struct {
	Home          string
	WorkDir       string
	AllowFiles    []string
	AllowDirs     []string
	DenyFiles     []string
	DenyDirs      []string
	ReadOnlyFiles []string
	ReadOnlyDirs  []string
	Hide          string
	Exec          []string
	Network       policy.Network
	AllowNet      []string
}

// Prepare resolves cfg into the paths a backend enforces.
// The working directory must not be the home directory or contain it.
func Prepare(cfg policy.Config, workDir, home, configDir string) (Plan, error) {
	if !cfg.Network.Valid() {
		return Plan{}, fmt.Errorf("%w: network %q", policy.ErrInvalid, cfg.Network)
	}
	homePath, ok, err := canonical(home)
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{}, fmt.Errorf("%w: home directory is missing", policy.ErrInvalid)
	}
	work, ok, err := canonical(workDir)
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{}, fmt.Errorf("%w: working directory is missing", policy.ErrInvalid)
	}
	if encloses(work, homePath) {
		return Plan{}, fmt.Errorf("%w: working directory %s exposes %s", policy.ErrScope, work, homePath)
	}
	hide, _, err := canonical(configDir)
	if err != nil {
		return Plan{}, err
	}
	allowFiles, allowDirs, err := allowed(cfg.AllowedPaths, homePath, hide)
	if err != nil {
		return Plan{}, err
	}
	files, dirs, err := denied(cfg.DenyRead, work, homePath)
	if err != nil {
		return Plan{}, err
	}
	roFiles, roDirs, extra, err := scanExposed(slices.Concat([]string{work}, allowDirs, allowFiles), files)
	if err != nil {
		return Plan{}, err
	}
	files = appendUnique(files, extra...)
	allowFiles = dropSame(allowFiles, files)
	allowDirs = dropSame(allowDirs, dirs)
	execs, err := executables(cfg.DenyExec, work)
	if err != nil {
		return Plan{}, err
	}
	hosts, err := normHosts(cfg.AllowNet)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Home:          homePath,
		WorkDir:       work,
		AllowFiles:    allowFiles,
		AllowDirs:     allowDirs,
		DenyFiles:     files,
		DenyDirs:      dirs,
		ReadOnlyFiles: roFiles,
		ReadOnlyDirs:  roDirs,
		Hide:          hide,
		Exec:          execs,
		Network:       cfg.Network,
		AllowNet:      hosts,
	}, nil
}

func allowed(paths []string, home, hide string) (files, dirs []string, err error) {
	for _, path := range paths {
		resolved, ok, err := canonical(path)
		if err != nil {
			return nil, nil, err
		}
		if !ok || policy.SameAlias(resolved, hide) {
			continue
		}
		if encloses(resolved, home) {
			return nil, nil, fmt.Errorf("%w: allowed path %s exposes %s", policy.ErrScope, resolved, home)
		}
		info, err := os.Lstat(resolved)
		if err != nil {
			return nil, nil, err
		}
		if info.IsDir() {
			dirs = appendUnique(dirs, resolved)
			continue
		}
		files = appendUnique(files, resolved)
	}
	return files, dirs, nil
}

func denied(patterns []string, work, home string) (files, dirs []string, err error) {
	for _, pattern := range patterns {
		matches, err := policy.ExpandMany(pattern, work, home)
		if err != nil {
			return nil, nil, err
		}
		for _, match := range matches {
			resolved, ok, err := canonical(match)
			if err != nil {
				return nil, nil, err
			}
			if !ok {
				continue
			}
			info, err := os.Lstat(resolved)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return nil, nil, err
			}
			if info.IsDir() {
				dirs = appendUnique(dirs, resolved)
				continue
			}
			files = appendUnique(files, resolved)
		}
	}
	return files, dirs, nil
}

func scanExposed(roots, denyFiles []string) (roFiles, roDirs, extra []string, err error) {
	linked := map[fileKey]struct{}{}
	for _, path := range denyFiles {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, nil, nil, err
		}
		if st, ok := statOf(info); ok && st.Nlink > 1 {
			linked[fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}] = struct{}{}
		}
	}
	for _, root := range roots {
		info, err := os.Lstat(root)
		if err != nil {
			return nil, nil, nil, err
		}
		if !info.IsDir() {
			noteExposed(root, info, linked, &roFiles, &roDirs, &extra)
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			noteExposed(path, info, linked, &roFiles, &roDirs, &extra)
			return nil
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return roFiles, roDirs, extra, nil
}

// noteExposed records a sensitive name, including a symlink, and a hard link of a denied file.
func noteExposed(path string, info os.FileInfo, linked map[fileKey]struct{}, files, dirs, extra *[]string) {
	if info.Mode()&os.ModeSymlink != 0 {
		if slices.Contains(sensitive, info.Name()) {
			*files = appendUnique(*files, path)
		}
		return
	}
	if slices.Contains(sensitive, info.Name()) {
		if info.IsDir() {
			*dirs = appendUnique(*dirs, path)
		} else {
			*files = appendUnique(*files, path)
		}
	}
	if info.IsDir() {
		return
	}
	st, ok := statOf(info)
	if !ok || st.Nlink < 2 {
		return
	}
	if _, found := linked[fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}]; found {
		*extra = appendUnique(*extra, path)
	}
}

func executables(rules []string, work string) ([]string, error) {
	var out []string
	for _, rule := range rules {
		if len(strings.Fields(rule)) != 1 {
			continue
		}
		if found, err := exec.LookPath(rule); err == nil {
			out = addBinary(out, found)
		}
		out = addBinary(out, filepath.Join(work, rule))
	}
	return out, nil
}

// addBinary records a denied binary and, when that path is a symlink, its target.
func addBinary(dst []string, path string) []string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return dst
	}
	abs = filepath.Clean(abs)
	info, err := os.Lstat(abs)
	if err != nil {
		return dst
	}
	if info.Mode()&os.ModeSymlink == 0 {
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return appendUnique(dst, abs)
		}
		return appendUnique(dst, resolved)
	}
	dst = appendUnique(dst, abs)
	if parent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		dst = appendUnique(dst, filepath.Join(parent, filepath.Base(abs)))
	}
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return dst
	}
	return appendUnique(dst, target)
}

func normHosts(hosts []string) ([]string, error) {
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		name, err := policy.NormHost(host)
		if err != nil {
			return nil, err
		}
		out = appendUnique(out, name)
	}
	return out, nil
}

func canonical(path string) (string, bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	abs = filepath.Clean(abs)
	if _, err := os.Lstat(abs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return abs, false, nil
		}
		return "", false, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false, err
	}
	if !policy.SameAlias(abs, resolved) {
		return "", false, fmt.Errorf("%w: %s", policy.ErrSymlink, path)
	}
	return resolved, true, nil
}

func encloses(parent, child string) bool {
	parent = policy.AppleAlias(filepath.Clean(parent))
	child = policy.AppleAlias(filepath.Clean(child))
	rel, err := filepath.Rel(parent, child)
	if err != nil || rel == ".." {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func dropSame(dst, gone []string) []string {
	var out []string
	for _, path := range dst {
		if slices.ContainsFunc(gone, func(other string) bool {
			return policy.SameAlias(path, other)
		}) {
			continue
		}
		out = append(out, path)
	}
	return out
}

func appendUnique(dst []string, paths ...string) []string {
	for _, path := range paths {
		if !slices.Contains(dst, path) {
			dst = append(dst, path)
		}
	}
	return dst
}

type fileKey struct {
	dev uint64
	ino uint64
}

func statOf(info os.FileInfo) (*syscall.Stat_t, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
