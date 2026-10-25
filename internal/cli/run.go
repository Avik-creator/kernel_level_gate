package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	box, err := enforce.ForOS(runtime.GOOS)
	if err != nil {
		return 1, err
	}
	launch, err := box.BuildArgs(plan, command)
	if err != nil {
		return 1, err
	}
	defer launch.Close()
	if err := audit.Write(dir, audit.Event{
		Kind:    audit.KindLaunch,
		Command: slices.Clone(command),
		WorkDir: plan.WorkDir,
	}); err != nil {
		return 1, err
	}
	err = start(launch, plan.WorkDir, stdin, stdout, stderr, cfg.MaskStdout)
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func start(launch enforce.Launch, work string, stdin io.Reader, stdout, stderr io.Writer, rules policy.MaskStdout) error {
	cmd := exec.Command(launch.Argv[0], launch.Argv[1:]...)
	cmd.Dir = work
	var info *os.File
	if len(launch.Files) == 2 {
		cmd.ExtraFiles = []*os.File{launch.Files[0]}
		info = launch.Files[1]
		defer launch.Files[0].Close()
	}
	masking := len(rules.Presets) > 0 || len(rules.Patterns) > 0
	if terminal(stdin) && terminal(stdout) {
		return runTerminal(cmd, info, launch.Slirp, stdin.(*os.File), stdout, rules, masking)
	}
	return runPipes(cmd, info, launch.Slirp, stdin, stdout, stderr, rules, masking)
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
		stop(cmd)
		return err
	}
	err = cmd.Wait()
	stop(proc)
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
		stop(cmd)
		return err
	}
	dst := stdout
	var flush flusher
	if masking {
		writer, err := mask.NewWriter(stdout, rules)
		if err != nil {
			stop(cmd)
			stop(proc)
			return err
		}
		dst = writer
		flush = writer
	}
	go io.Copy(ptmx, stdin)
	_, copyErr := io.Copy(dst, ptmx)
	waitErr := cmd.Wait()
	stop(proc)
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

func stop(proc *exec.Cmd) {
	if proc == nil || proc.Process == nil {
		return
	}
	_ = proc.Process.Kill()
	_ = proc.Wait()
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
