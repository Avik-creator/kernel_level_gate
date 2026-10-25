package policy

import (
	"fmt"
	"regexp"
	"slices"
)

// Merge applies a project overlay onto base.
// The overlay may shrink allow lists, lower the network mode, and add denies.
func Merge(base Config, over Overlay, home string) (Config, error) {
	if !base.Network.Valid() {
		return Config{}, fmt.Errorf("%w: network %q", ErrInvalid, base.Network)
	}
	out := base
	var err error
	if out.AllowNet, err = canonHosts(base.AllowNet); err != nil {
		return Config{}, err
	}
	if out.AllowedPaths, err = canonPaths(base.AllowedPaths, home); err != nil {
		return Config{}, err
	}
	if out.DenyRead, err = canonPaths(base.DenyRead, home); err != nil {
		return Config{}, err
	}
	if out.DenyExec, err = canonPaths(base.DenyExec, home); err != nil {
		return Config{}, err
	}
	if out.MaskStdout, err = unionMask(base.MaskStdout, nil); err != nil {
		return Config{}, err
	}
	if over.Network != nil {
		mode := *over.Network
		if !mode.Valid() {
			return Config{}, fmt.Errorf("%w: network %q", ErrInvalid, mode)
		}
		if Openness(mode) > Openness(base.Network) {
			return Config{}, fmt.Errorf("%w: network %q", ErrWiden, mode)
		}
		out.Network = mode
	}
	if over.AllowNet != nil {
		if out.AllowNet, err = narrowHosts(base.AllowNet, *over.AllowNet); err != nil {
			return Config{}, err
		}
	}
	if over.AllowedPaths != nil {
		if out.AllowedPaths, err = narrowPaths(base.AllowedPaths, *over.AllowedPaths, home); err != nil {
			return Config{}, err
		}
	}
	if over.DenyRead != nil {
		if out.DenyRead, err = unionPaths(base.DenyRead, *over.DenyRead, home); err != nil {
			return Config{}, err
		}
	}
	if over.DenyExec != nil {
		if out.DenyExec, err = unionPaths(base.DenyExec, *over.DenyExec, home); err != nil {
			return Config{}, err
		}
	}
	if over.MaskStdout != nil {
		if out.MaskStdout, err = unionMask(base.MaskStdout, over.MaskStdout); err != nil {
			return Config{}, err
		}
	}
	return out, nil
}

// Widen applies one-shot allow-net and allow-path additions.
// allow-net is refused unless the network mode is restricted.
func Widen(cfg Config, allowNet, allowPaths []string, home string) (Config, error) {
	if len(allowNet) > 0 && cfg.Network != NetworkRestricted {
		return Config{}, fmt.Errorf("%w: allow-net applies only when network is restricted", ErrInvalid)
	}
	out, err := Merge(cfg, Overlay{}, home)
	if err != nil {
		return Config{}, err
	}
	for _, host := range allowNet {
		name, err := NormHost(host)
		if err != nil {
			return Config{}, err
		}
		if slices.Contains(out.AllowNet, name) {
			continue
		}
		out.AllowNet = append(out.AllowNet, name)
	}
	for _, path := range allowPaths {
		key, err := PatternKey(path, home)
		if err != nil {
			return Config{}, err
		}
		if slices.Contains(out.AllowedPaths, key) {
			continue
		}
		out.AllowedPaths = append(out.AllowedPaths, key)
	}
	return out, nil
}

func canonHosts(hosts []string) ([]string, error) {
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		name, err := NormHost(host)
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

func narrowHosts(base, want []string) ([]string, error) {
	have, err := canonHosts(base)
	if err != nil {
		return nil, err
	}
	got, err := canonHosts(want)
	if err != nil {
		return nil, err
	}
	for _, host := range got {
		if !slices.Contains(have, host) {
			return nil, fmt.Errorf("%w: host %q", ErrWiden, host)
		}
	}
	return got, nil
}

func canonPaths(paths []string, home string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		key, err := PatternKey(path, home)
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, key) {
			continue
		}
		out = append(out, key)
	}
	return out, nil
}

func narrowPaths(base, want []string, home string) ([]string, error) {
	have, err := canonPaths(base, home)
	if err != nil {
		return nil, err
	}
	got, err := canonPaths(want, home)
	if err != nil {
		return nil, err
	}
	for _, path := range got {
		if !slices.Contains(have, path) {
			return nil, fmt.Errorf("%w: path %q", ErrWiden, path)
		}
	}
	return got, nil
}

func unionPaths(base, extra []string, home string) ([]string, error) {
	return canonPaths(slices.Concat(base, extra), home)
}

func unionMask(base MaskStdout, extra *MaskStdout) (MaskStdout, error) {
	out := MaskStdout{
		Presets:  slices.Clone(base.Presets),
		Patterns: slices.Clone(base.Patterns),
	}
	for _, pattern := range out.Patterns {
		if err := validMask(pattern); err != nil {
			return MaskStdout{}, err
		}
	}
	if extra == nil {
		return out, nil
	}
	for _, preset := range extra.Presets {
		if preset == "" {
			return MaskStdout{}, fmt.Errorf("%w: empty mask preset", ErrInvalid)
		}
		if slices.Contains(out.Presets, preset) {
			continue
		}
		out.Presets = append(out.Presets, preset)
	}
	for _, pattern := range extra.Patterns {
		if err := validMask(pattern); err != nil {
			return MaskStdout{}, err
		}
		out.Patterns = append(out.Patterns, pattern)
	}
	return out, nil
}

func validMask(pattern MaskPattern) error {
	if pattern.Regex == "" || pattern.ShowPrefix < 0 {
		return fmt.Errorf("%w: mask pattern", ErrInvalid)
	}
	if _, err := regexp.Compile(pattern.Regex); err != nil {
		return fmt.Errorf("%w: mask regex: %v", ErrInvalid, err)
	}
	return nil
}
