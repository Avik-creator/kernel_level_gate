package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"kernel_level_gate/internal/policy"
)

const FileName = "audit.jsonl"

const (
	KindLaunch = "launch"
	KindBlock  = "block"
)

// Event is one JSON line. Kernel denials are not events: they return EPERM.
type Event struct {
	Time    time.Time `json:"time,omitzero"`
	Kind    string    `json:"kind"`
	Command []string  `json:"command,omitempty"`
	WorkDir string    `json:"work_dir,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// Write appends ev to dir/audit.jsonl with mode 0600.
// A symlink at the directory or the file is refused.
func Write(dir string, ev Event) error {
	if dir == "" {
		return fmt.Errorf("%w: audit directory is empty", policy.ErrInvalid)
	}
	if ev.Kind != KindLaunch && ev.Kind != KindBlock {
		return fmt.Errorf("%w: audit kind %q", policy.ErrInvalid, ev.Kind)
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.Time = ev.Time.UTC()
	if err := ensureDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, FileName)
	if err := rejectSymlink(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: %s", policy.ErrSymlink, path)
		}
		return err
	}
	defer file.Close()
	if err := sameRegular(file, path); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		return err
	}
	if _, err := file.Write(buf.Bytes()); err != nil {
		return err
	}
	return file.Sync()
}

func ensureDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", policy.ErrSymlink, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", policy.ErrInvalid, dir)
	}
	return os.Chmod(dir, 0o700)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", policy.ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a file", policy.ErrInvalid, path)
	}
	return nil
}

func sameRegular(file *os.File, path string) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, linked) {
		return fmt.Errorf("%w: %s", policy.ErrSymlink, path)
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if ok && st.Nlink > 1 {
		return fmt.Errorf("%w: %s has another hard link", policy.ErrInvalid, path)
	}
	return nil
}
