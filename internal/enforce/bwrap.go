package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"kernel_level_gate/internal/policy"
)

// Linux is a bwrap launch.
// The runner writes Script and Resolv, then appends the child pid and tap0 to Slirp.
type Linux struct {
	Argv   []string
	Script string
	Resolv string
	Slirp  []string
}

const netScript = `#!/bin/sh
set -eu
hosts=
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
  case "$1" in
    *[!A-Za-z0-9._:-]*)
      echo "kgate: invalid host" >&2
      exit 125
      ;;
  esac
  hosts="$hosts $1"
  shift
done
if [ "${1-}" != "--" ]; then
  echo "kgate: missing command" >&2
  exit 125
fi
shift
i=0
while [ "$i" -lt 50 ]; do
  if ip -4 addr show dev tap0 2>/dev/null | grep -q '10.0.2.100/'; then
    break
  fi
  i=$((i + 1))
  sleep 0.1
done
if ! ip -4 addr show dev tap0 2>/dev/null | grep -q '10.0.2.100/'; then
  echo "kgate: network namespace was not configured" >&2
  exit 125
fi
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 10.0.2.3 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 10.0.2.3 -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 10.0.2.3 -j REJECT
for host in $hosts; do
  count=0
  ips=$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)
  for ip in $ips; do
    case "$ip" in
      *[!0-9.]*) echo "kgate: bad address" >&2; exit 125 ;;
    esac
    iptables -A OUTPUT -d "$ip" -j ACCEPT
    count=$((count + 1))
  done
  if [ "$count" -eq 0 ]; then
    echo "kgate: no address" >&2
    exit 125
  fi
done
v6_off=1
if [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
  v6_off=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
fi
if [ "$v6_off" = 0 ]; then
  command -v ip6tables >/dev/null || { echo "kgate: ip6tables is required" >&2; exit 125; }
  ip6tables -P OUTPUT DROP
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A OUTPUT -d fd00::3 -p udp --dport 53 -j ACCEPT
  ip6tables -A OUTPUT -d fd00::3 -p tcp --dport 53 -j ACCEPT
  ip6tables -A OUTPUT -d fd00::3 -j REJECT
  for host in $hosts; do
    ips=$(getent ahostsv6 "$host" | awk '{print $1}' | sort -u)
    for ip in $ips; do
      case "$ip" in
        *[!0-9A-Fa-f:]*) echo "kgate: bad address" >&2; exit 125 ;;
      esac
      ip6tables -A OUTPUT -d "$ip" -j ACCEPT
    done
  done
  ip6tables -A OUTPUT -j REJECT
fi
iptables -A OUTPUT -j REJECT
exec "$@"
`

// Bubblewrap returns the bwrap argv for plan.
// The child command stays in argv. A host allow list also returns the net script and the host slirp4netns args.
func Bubblewrap(plan Plan, scriptPath, resolvPath string, command []string) (Linux, error) {
	if len(command) == 0 {
		return Linux{}, fmt.Errorf("%w: command is empty", policy.ErrInvalid)
	}
	if !plan.Network.Valid() {
		return Linux{}, fmt.Errorf("%w: network %q", policy.ErrInvalid, plan.Network)
	}
	hosts, err := normHosts(plan.AllowNet)
	if err != nil {
		return Linux{}, err
	}
	slirp := plan.Network == policy.NetworkRestricted && len(hosts) > 0
	if slirp {
		if err := absolute(scriptPath); err != nil {
			return Linux{}, err
		}
		if err := absolute(resolvPath); err != nil {
			return Linux{}, err
		}
	}
	argv := []string{
		"bwrap",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--unshare-user",
		"--unshare-pid",
		"--die-with-parent",
	}
	if plan.Network != policy.NetworkOpen {
		argv = append(argv, "--unshare-net")
	}
	if err := bind(&argv, "--tmpfs", plan.Home); err != nil {
		return Linux{}, err
	}
	if err := bind(&argv, "--bind", plan.WorkDir, plan.WorkDir); err != nil {
		return Linux{}, err
	}
	for _, path := range plan.AllowDirs {
		if err := bind(&argv, "--bind", path, path); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.AllowFiles {
		if err := bind(&argv, "--bind", path, path); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.ReadOnlyDirs {
		if err := bind(&argv, "--ro-bind", path, path); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.ReadOnlyFiles {
		from := path
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			from = "/dev/null"
		}
		if err := bind(&argv, "--ro-bind", from, path); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.DenyFiles {
		if err := bind(&argv, "--ro-bind", "/dev/null", path); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.DenyDirs {
		if err := bind(&argv, "--tmpfs", path); err != nil {
			return Linux{}, err
		}
	}
	if plan.Hide != "" {
		if err := bind(&argv, "--tmpfs", plan.Hide); err != nil {
			return Linux{}, err
		}
	}
	for _, path := range plan.Exec {
		if err := bind(&argv, "--ro-bind", "/dev/null", path); err != nil {
			return Linux{}, err
		}
	}
	out := Linux{Argv: argv}
	if slirp {
		if err := bind(&argv, "--ro-bind", resolvPath, "/etc/resolv.conf"); err != nil {
			return Linux{}, err
		}
		if err := bind(&argv, "--ro-bind", scriptPath, "/tmp/kgate-net.sh"); err != nil {
			return Linux{}, err
		}
		out.Script = netScript
		out.Resolv = "nameserver 10.0.2.3\n"
		out.Slirp = []string{"slirp4netns", "--configure", "--mtu=65520", "--disable-host-loopback"}
		argv = append(argv, "--", "/bin/sh", "/tmp/kgate-net.sh")
		argv = append(argv, hosts...)
		argv = append(argv, "--")
	} else {
		argv = append(argv, "--")
	}
	out.Argv = append(argv, command...)
	return out, nil
}

// LinuxNetTools reports whether a host allow list can be installed.
func LinuxNetTools(plan Plan) error {
	if plan.Network != policy.NetworkRestricted || len(plan.AllowNet) == 0 {
		return nil
	}
	for _, tool := range []string{"slirp4netns", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%w: %s is required for a host allow list", policy.ErrNetwork, tool)
		}
	}
	return nil
}

func bind(argv *[]string, flag string, paths ...string) error {
	for _, path := range paths {
		if err := absolute(path); err != nil {
			return err
		}
	}
	*argv = append(*argv, flag)
	*argv = append(*argv, paths...)
	return nil
}

func absolute(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("%w: path %q", policy.ErrInvalid, path)
	}
	return nil
}
