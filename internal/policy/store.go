package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	configName   = "config.yaml"
	configHeader = "# kgate global policy. A project .kgate.yaml can only tighten this.\n"
)

// GlobalDir is ~/.kgate, or KGATE_CONFIG_DIR when that variable is set.
func GlobalDir() (string, error) {
	if dir := os.Getenv("KGATE_CONFIG_DIR"); dir != "" {
		return filepath.Clean(dir), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kgate"), nil
}

// Load reads the global config. A missing directory or file is ErrNotInitialized.
func Load(dir string) (Config, error) {
	if err := ensureDir(dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, ErrNotInitialized
		}
		return Config{}, err
	}
	file, err := openRegular(filepath.Join(dir, configName))
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNotInitialized
	}
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	var cfg Config
	if err := decodeYAML(file, &cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("%w: empty config", ErrInvalid)
		}
		return Config{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !cfg.Network.Valid() {
		return Config{}, fmt.Errorf("%w: network %q", ErrInvalid, cfg.Network)
	}
	return cfg, nil
}

// Save writes config.yaml with mode 0600. The directory is created at 0700.
// A symlink at either path is refused.
func Save(dir string, cfg Config) error {
	if !cfg.Network.Valid() {
		return fmt.Errorf("%w: network %q", ErrInvalid, cfg.Network)
	}
	if err := ensureDir(dir, true); err != nil {
		return err
	}
	path := filepath.Join(dir, configName)
	if err := rejectSpecial(path, true); err != nil {
		return err
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return writeFile(dir, path, append([]byte(configHeader), body...))
}

// LoadProject reads a project overlay. A missing file is an empty overlay.
func LoadProject(path string) (Overlay, error) {
	file, err := openRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return Overlay{}, nil
	}
	if err != nil {
		return Overlay{}, err
	}
	defer file.Close()
	var over Overlay
	if err := decodeYAML(file, &over); err != nil {
		if errors.Is(err, io.EOF) {
			return Overlay{}, nil
		}
		return Overlay{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return over, nil
}

// RemoveGlobal deletes dir only when it is the configured global directory.
// A symlink is refused, so the target is left in place.
func RemoveGlobal(dir string) error {
	dir = filepath.Clean(dir)
	if err := removalAllowed(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotInitialized
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInvalid, dir)
	}
	return os.RemoveAll(dir)
}

func removalAllowed(dir string) error {
	if env := os.Getenv("KGATE_CONFIG_DIR"); env != "" {
		if dir != filepath.Clean(env) {
			return fmt.Errorf("%w: refusing to remove %s", ErrInvalid, dir)
		}
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if dir != filepath.Join(home, ".kgate") {
		return fmt.Errorf("%w: refusing to remove %s", ErrInvalid, dir)
	}
	return nil
}

func ensureDir(dir string, create bool) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInvalid, dir)
	}
	if create {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

func rejectSpecial(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a file", ErrInvalid, path)
	}
	return nil
}

func openRegular(path string) (*os.File, error) {
	if err := rejectSpecial(path, false); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	linked, err := os.Lstat(path)
	if err != nil {
		file.Close()
		return nil, err
	}
	if !os.SameFile(opened, linked) {
		file.Close()
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	return file, nil
}

func decodeYAML(file *os.File, dest any) error {
	dec := yaml.NewDecoder(file)
	dec.KnownFields(true)
	return dec.Decode(dest)
}

func writeFile(dir, path string, body []byte) error {
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return err
	}
	name := tmp.Name()
	done := false
	defer func() {
		if !done {
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	done = true
	return nil
}
