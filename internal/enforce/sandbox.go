package enforce

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"kernel_level_gate/internal/policy"
)

// Sandbox is the kernel backend for this operating system.
type Sandbox interface {
	BuildArgs(plan Plan, command []string) (Launch, error)
	Doctor(network policy.Network, hosts []string) Verdict
}

// Verdict is what doctor reports for this backend.
type Verdict struct {
	Word   string
	Detail string
	Code   int
}

// Launch is the process the runner starts.
// Files is the fd 3 pipe, write end first. Close is set when BuildArgs succeeds.
type Launch struct {
	Argv  []string
	Files []*os.File
	Slirp []string
	Close func()
}

// ForOS returns the backend that can run on goos.
func ForOS(goos string) (Sandbox, error) {
	switch goos {
	case "darwin":
		return seatbeltSandbox{}, nil
	case "linux":
		return bwrapSandbox{}, nil
	default:
		return nil, policy.ErrUnsupported
	}
}

type seatbeltSandbox struct{}

type bwrapSandbox struct{}

func (seatbeltSandbox) Doctor(network policy.Network, _ []string) Verdict {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return Verdict{Word: "BLOCKED", Detail: "sandbox-exec is not installed.", Code: 1}
	}
	if network == policy.NetworkOpen {
		return openVerdict()
	}
	if err := seatbeltNetwork(network); err != nil {
		detail := err.Error()
		if errors.Is(err, policy.ErrNetwork) {
			detail = "network restricted cannot be enforced by " + seatbeltHostLimit + ". Run kgate network off or kgate network open."
		}
		return Verdict{Word: "BLOCKED", Detail: detail, Code: 1}
	}
	return Verdict{Word: "READY", Detail: "sandbox-exec can enforce this policy.", Code: 0}
}

func (bwrapSandbox) Doctor(network policy.Network, hosts []string) Verdict {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return Verdict{Word: "BLOCKED", Detail: "bwrap is not installed.", Code: 1}
	}
	if network == policy.NetworkOpen {
		return openVerdict()
	}
	if err := LinuxNetTools(Plan{Network: network, AllowNet: hosts}); err != nil {
		return Verdict{Word: "BLOCKED", Detail: err.Error(), Code: 1}
	}
	return Verdict{Word: "READY", Detail: "bwrap can enforce this policy.", Code: 0}
}

func openVerdict() Verdict {
	return Verdict{Word: "DEGRADED", Detail: "network open does not restrict egress.", Code: 0}
}

func (seatbeltSandbox) BuildArgs(plan Plan, command []string) (Launch, error) {
	argv, err := Seatbelt(plan, command)
	if err != nil {
		return Launch{}, err
	}
	return Launch{Argv: argv, Close: func() {}}, nil
}

func (bwrapSandbox) BuildArgs(plan Plan, command []string) (Launch, error) {
	if err := LinuxNetTools(plan); err != nil {
		return Launch{}, err
	}
	dir, err := os.MkdirTemp("", "kgate-")
	if err != nil {
		return Launch{}, err
	}
	out, err := bwrapIn(dir, plan, command)
	if err != nil {
		os.RemoveAll(dir)
		return Launch{}, err
	}
	return out, nil
}

func bwrapIn(dir string, plan Plan, command []string) (Launch, error) {
	closer := func() { os.RemoveAll(dir) }
	scriptPath := filepath.Join(dir, "net.sh")
	resolvPath := filepath.Join(dir, "resolv.conf")
	lin, err := Bubblewrap(plan, scriptPath, resolvPath, command)
	if err != nil {
		return Launch{}, err
	}
	out := Launch{Argv: lin.Argv, Slirp: lin.Slirp, Close: closer}
	if lin.Script == "" {
		return out, nil
	}
	if err := os.WriteFile(scriptPath, []byte(lin.Script), 0o700); err != nil {
		return Launch{}, err
	}
	if err := os.WriteFile(resolvPath, []byte(lin.Resolv), 0o600); err != nil {
		return Launch{}, err
	}
	argv, err := withInfoFd(lin.Argv)
	if err != nil {
		return Launch{}, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return Launch{}, err
	}
	out.Argv = argv
	out.Files = []*os.File{writer, reader}
	out.Close = func() {
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

var (
	_ Sandbox = seatbeltSandbox{}
	_ Sandbox = bwrapSandbox{}
)
