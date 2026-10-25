package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"

	"github.com/creack/pty"
	"golang.org/x/term"

	"kernel_level_gate/internal/audit"
	"kernel_level_gate/internal/enforce"
	"kernel_level_gate/internal/mask"
	"kernel_level_gate/internal/policy"
)

func cmdRun(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var hosts, paths stringList
	fs.Var(&hosts, "allow-net", "host to allow for this launch")
	fs.Var(&paths, "allow-path", "path to allow for this launch")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	command := fs.Args()
	if len(command) == 0 {
		return 1, fmt.Errorf("%w: command is empty", policy.ErrInvalid)
	}
	dir, err := policy.GlobalDir()
	if err != nil {
		return 1, err
	}
	cfg, err := effective()
	if err != nil {
		return 1, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, err
	}
	work, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	cfg, err = policy.Widen(cfg, hosts, paths, home)
	if err != nil {
		return 1, err
	}
	plan, err := enforce.Prepare(cfg, work, home, dir)
	if err != nil {
		return 1, err
	}
	if err := policy.CheckCommand(command, cfg.DenyExec); err != nil {
		if errors.Is(err, policy.ErrBlocked) {
			if werr := audit.Write(dir, audit.Event{
				Kind:    audit.KindBlock,
				Command: slices.Clone(command),
				WorkDir: plan.WorkDir,
				Reason:  err.Error(),
			}); werr != nil {
				return 1, werr
			}
		}
		return 1, err
	}
	argv, files, slirp, cleanup, err := sandbox(plan, command)
	if err != nil {
		return 1, err
	}
	defer cleanup()
	if err := audit.Write(dir, audit.Event{
		Kind:    audit.KindLaunch,
		Command: slices.Clone(command),
		WorkDir: plan.WorkDir,
	}); err != nil {
		return 1, err
	}
	err = start(argv, files, slirp, plan.WorkDir, stdin, stdout, stderr, cfg.MaskStdout)
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

type prepared struct {
	argv   []string
	files  []*os.File
	slirp  []string
	closer func()
}

func sandbox(plan enforce.Plan, command []string) (argv []string, files []*os.File, slirp []string, cleanup func(), err error) {
	noop := func() {}
	switch runtime.GOOS {
	case "darwin":
		argv, err = enforce.Seatbelt(plan, command)
		return argv, nil, nil, noop, err
	case "linux":
		got, err := prepareLinux(plan, command)
		if err != nil {
			return nil, nil, nil, noop, err
		}
		return got.argv, got.files, got.slirp, got.closer, nil
	default:
		return nil, nil, nil, noop, policy.ErrUnsupported
	}
}

func prepareLinux(plan enforce.Plan, command []string) (prepared, error) {
	if err := enforce.LinuxNetTools(plan); err != nil {
		return prepared{}, err
	}
	dir, err := os.MkdirTemp("", "kgate-")
	if err != nil {
		return prepared{}, err
	}
	closer := func() { os.RemoveAll(dir) }
	scriptPath := filepath.Join(dir, "net.sh")
	resolvPath := filepath.Join(dir, "resolv.conf")
	lin, err := enforce.Bubblewrap(plan, scriptPath, resolvPath, command)
	if err != nil {
		closer()
		return prepared{}, err
	}
	out := prepared{argv: lin.Argv, slirp: lin.Slirp, closer: closer}
	if lin.Script == "" {
		return out, nil
	}
	if err := os.WriteFile(scriptPath, []byte(lin.Script), 0o700); err != nil {
		closer()
		return prepared{}, err
	}
	if err := os.WriteFile(resolvPath, []byte(lin.Resolv), 0o600); err != nil {
		closer()
		return prepared{}, err
	}
	argv, err := withInfoFd(lin.Argv)
	if err != nil {
		closer()
		return prepared{}, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		closer()
		return prepared{}, err
	}
	out.argv = argv
	out.slirp = lin.Slirp
	out.files = []*os.File{writer, reader}
	out.closer = func() {
		reader.Close()
		writer.Close()
		closer()
	}
	return out, nil
}

// withInfoFd asks bwrap to report the sandboxed pid on fd 3.
func withInfoFd(argv []string) ([]string, error) {
	at := slices.Index(argv, "--")
	if at < 0 {
		return nil, fmt.Errorf("%w: sandbox command is missing", policy.ErrInvalid)
	}
	out := slices.Clone(argv[:at])
	out = append(out, "--info-fd", "3")
	return append(out, argv[at:]...), nil
}

func start(argv []string, files []*os.File, slirp []string, work string, stdin io.Reader, stdout, stderr io.Writer, rules policy.MaskStdout) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = work
	var info *os.File
	if len(files) == 2 {
		cmd.ExtraFiles = []*os.File{files[0]}
		info = files[1]
		defer files[0].Close()
	}
	masking := len(rules.Presets) > 0 || len(rules.Patterns) > 0
	if terminal(stdin) && terminal(stdout) {
		return runTerminal(cmd, info, slirp, stdin.(*os.File), stdout, rules, masking)
	}
	return runPipes(cmd, info, slirp, stdin, stdout, stderr, rules, masking)
}

func runPipes(cmd *exec.Cmd, info *os.File, slirp []string, stdin io.Reader, stdout, stderr io.Writer, rules policy.MaskStdout, masking bool) error {
	var flushers []flusher
	if masking {
		out, err := mask.NewWriter(stdout, rules)
		if err != nil {
			return err
		}
		errOut, err := mask.NewWriter(stderr, rules)
		if err != nil {
			return err
		}
		stdout, stderr = out, errOut
		flushers = []flusher{out, errOut}
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	proc, err := attachSlirp(info, slirp)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	err = cmd.Wait()
	if proc != nil {
		_ = proc.Process.Kill()
		_ = proc.Wait()
	}
	for _, one := range flushers {
		if ferr := one.Flush(); err == nil {
			err = ferr
		}
	}
	return err
}

func runTerminal(cmd *exec.Cmd, info *os.File, slirp []string, stdin *os.File, stdout io.Writer, rules policy.MaskStdout, masking bool) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	if state, err := term.MakeRaw(int(stdin.Fd())); err == nil {
		defer term.Restore(int(stdin.Fd()), state)
	}
	proc, err := attachSlirp(info, slirp)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	dst := stdout
	var flush flusher
	if masking {
		writer, err := mask.NewWriter(stdout, rules)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
		dst = writer
		flush = writer
	}
	go io.Copy(ptmx, stdin)
	_, copyErr := io.Copy(dst, ptmx)
	waitErr := cmd.Wait()
	if proc != nil {
		_ = proc.Process.Kill()
		_ = proc.Wait()
	}
	if flush != nil {
		if ferr := flush.Flush(); waitErr == nil {
			waitErr = ferr
		}
	}
	if waitErr != nil {
		return waitErr
	}
	return copyErr
}

func attachSlirp(info *os.File, args []string) (*exec.Cmd, error) {
	if info == nil {
		return nil, nil
	}
	defer info.Close()
	var meta struct {
		ChildPID int `json:"child-pid"`
	}
	if err := json.NewDecoder(info).Decode(&meta); err != nil {
		return nil, fmt.Errorf("%w: sandbox pid: %v", policy.ErrInvalid, err)
	}
	if meta.ChildPID <= 0 || len(args) == 0 {
		return nil, fmt.Errorf("%w: sandbox pid is missing", policy.ErrInvalid)
	}
	slirp := exec.Command(args[0], append(slices.Clone(args[1:]), strconv.Itoa(meta.ChildPID), "tap0")...)
	slirp.Stdout = io.Discard
	slirp.Stderr = io.Discard
	if err := slirp.Start(); err != nil {
		return nil, err
	}
	return slirp, nil
}

func terminal(stream any) bool {
	file, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

type flusher interface {
	Flush() error
}

type stringList []string

func (s *stringList) String() string { return "" }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}
