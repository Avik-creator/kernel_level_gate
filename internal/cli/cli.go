package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"kernel_level_gate/internal/enforce"
	"kernel_level_gate/internal/policy"
)

const Version = "0.1.0"

const projectFile = ".kgate.yaml"

// Main runs one kgate invocation and returns its exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if args[0] == "version" || args[0] == "-version" || args[0] == "--version" {
		fmt.Fprintln(stdout, Version)
		return 0
	}
	code, err := dispatch(args, stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if code == 0 {
			return 1
		}
	}
	return code
}

func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	switch args[0] {
	case "init":
		return 0, cmdInit(args[1:])
	case "doctor":
		return cmdDoctor(stdout)
	case "status":
		return 0, cmdStatus(stdout)
	case "network":
		return 0, cmdNetwork(args[1:])
	case "allow", "deny":
		return 0, cmdEdit(args[0], args[1:])
	case "reset":
		return 0, cmdReset(args[1:])
	case "run":
		return cmdRun(args[1:], stdin, stdout, stderr)
	default:
		return 2, fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite an existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := policy.GlobalDir()
	if err != nil {
		return err
	}
	if _, err := policy.Load(dir); err == nil && !*force {
		return fmt.Errorf("%w: already initialized", policy.ErrInvalid)
	} else if err != nil && !errors.Is(err, policy.ErrNotInitialized) {
		return err
	}
	return policy.Save(dir, policy.Default())
}

func cmdDoctor(stdout io.Writer) (int, error) {
	cfg, err := effective()
	if errors.Is(err, policy.ErrNotInitialized) {
		fmt.Fprintf(stdout, "BLOCKED\n%s. Run kgate init.\n", policy.ErrNotInitialized)
		return 1, nil
	}
	if err != nil {
		return 1, err
	}
	word, detail, code := diagnose(cfg)
	fmt.Fprintf(stdout, "%s\n%s\n", word, detail)
	return code, nil
}

func diagnose(cfg policy.Config) (string, string, int) {
	box, err := enforce.ForOS(runtime.GOOS)
	if err != nil {
		return "BLOCKED", err.Error(), 1
	}
	verdict := box.Doctor(cfg.Network, cfg.AllowNet)
	return verdict.Word, verdict.Detail, verdict.Code
}

func cmdStatus(stdout io.Writer) error {
	dir, err := policy.GlobalDir()
	if err != nil {
		return err
	}
	cfg, err := policy.Load(dir)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "# global")
	fmt.Fprint(stdout, formatConfig(cfg))
	merged, err := effective()
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "# merged")
	fmt.Fprint(stdout, formatConfig(merged))
	return nil
}

func formatConfig(cfg policy.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "network: %s\n", cfg.Network)
	writeList(&b, "allow_net", cfg.AllowNet)
	writeList(&b, "allowed_paths", cfg.AllowedPaths)
	writeList(&b, "deny_read", cfg.DenyRead)
	writeList(&b, "deny_exec", cfg.DenyExec)
	return b.String()
}

func writeList(b *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n", name)
	for _, value := range values {
		fmt.Fprintf(b, "  - %s\n", value)
	}
}

func cmdNetwork(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: network needs off, open, or restricted", policy.ErrInvalid)
	}
	mode := policy.Network(args[0])
	if !mode.Valid() {
		return fmt.Errorf("%w: network %q", policy.ErrInvalid, mode)
	}
	return update(func(cfg policy.Config) (policy.Config, error) {
		cfg.Network = mode
		return cfg, nil
	})
}

func cmdEdit(verb string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("%w: %s needs a kind and a value", policy.ErrInvalid, verb)
	}
	kind, value := args[0], args[1]
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return update(func(cfg policy.Config) (policy.Config, error) {
		switch kind {
		case "net":
			return editHost(cfg, verb, value)
		case "path":
			return editPath(cfg, verb, value, home)
		case "read":
			return editList(cfg, verb, value, home, true)
		case "exec":
			return editList(cfg, verb, value, home, false)
		default:
			return cfg, fmt.Errorf("%w: unknown kind %q", policy.ErrInvalid, kind)
		}
	})
}

func editHost(cfg policy.Config, verb, value string) (policy.Config, error) {
	name, err := policy.NormHost(value)
	if err != nil {
		return cfg, err
	}
	if verb == "allow" {
		if !slices.Contains(cfg.AllowNet, name) {
			cfg.AllowNet = append(cfg.AllowNet, name)
		}
		return cfg, nil
	}
	cfg.AllowNet = slices.DeleteFunc(cfg.AllowNet, func(host string) bool {
		got, err := policy.NormHost(host)
		return err == nil && got == name
	})
	return cfg, nil
}

func editPath(cfg policy.Config, verb, value, home string) (policy.Config, error) {
	if verb == "allow" {
		key, err := policy.PatternKey(value, home)
		if err != nil {
			return cfg, err
		}
		if !slices.Contains(cfg.AllowedPaths, key) {
			cfg.AllowedPaths = append(cfg.AllowedPaths, key)
		}
		return cfg, nil
	}
	next, err := withoutKey(cfg.AllowedPaths, value, home)
	if err != nil {
		return cfg, err
	}
	cfg.AllowedPaths = next
	return cfg, nil
}

func editList(cfg policy.Config, verb, value, home string, read bool) (policy.Config, error) {
	list := cfg.DenyExec
	if read {
		list = cfg.DenyRead
	}
	var err error
	if verb == "deny" {
		key, keyErr := policy.PatternKey(value, home)
		if keyErr != nil {
			return cfg, keyErr
		}
		if !slices.Contains(list, key) {
			list = append(list, key)
		}
	} else {
		list, err = withoutKey(list, value, home)
		if err != nil {
			return cfg, err
		}
	}
	if read {
		cfg.DenyRead = list
	} else {
		cfg.DenyExec = list
	}
	return cfg, nil
}

func withoutKey(list []string, value, home string) ([]string, error) {
	key, err := policy.PatternKey(value, home)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list, func(item string) bool {
		got, err := policy.PatternKey(item, home)
		return err == nil && got == key
	}), nil
}

func cmdReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	force := fs.Bool("force", false, "delete the global config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*force {
		return fmt.Errorf("%w: reset requires --force", policy.ErrInvalid)
	}
	dir, err := policy.GlobalDir()
	if err != nil {
		return err
	}
	return policy.RemoveGlobal(dir)
}

func update(edit func(policy.Config) (policy.Config, error)) error {
	dir, err := policy.GlobalDir()
	if err != nil {
		return err
	}
	cfg, err := policy.Load(dir)
	if err != nil {
		return err
	}
	cfg, err = edit(cfg)
	if err != nil {
		return err
	}
	return policy.Save(dir, cfg)
}

func effective() (policy.Config, error) {
	dir, err := policy.GlobalDir()
	if err != nil {
		return policy.Config{}, err
	}
	cfg, err := policy.Load(dir)
	if err != nil {
		return policy.Config{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return policy.Config{}, err
	}
	work, err := os.Getwd()
	if err != nil {
		return policy.Config{}, err
	}
	over, err := policy.LoadProject(filepath.Join(work, projectFile))
	if err != nil {
		return policy.Config{}, err
	}
	return policy.Merge(cfg, over, home)
}

const usage = `kgate - kernel sandbox for an agent command

  kgate init [--force]
  kgate doctor
  kgate status
  kgate network off|open|restricted
  kgate allow net|path|read|exec VALUE
  kgate deny net|path|read|exec VALUE
  kgate run [--allow-net HOST] [--allow-path PATH] -- COMMAND
  kgate reset --force
  kgate version

doctor prints READY, DEGRADED, or BLOCKED.
A project .kgate.yaml can only tighten the global policy.
--allow-net and --allow-path widen one launch.
`
