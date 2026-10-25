# kernel_level_gate

Kernel-enforced sandbox for AI coding agents. The process runs under macOS Seatbelt or Linux bubblewrap, so file and network limits are applied by the operating system.

The module path is `kernel_level_gate`. The command is `kgate`.

https://github.com/user-attachments/assets/fed1c9f9-8ec7-4e4a-8a52-5cad1f36bb30

## Policy

A launch that cannot install the requested control does not start.

- **Filesystem scope is always on.** The working directory and the allowed paths are reachable. The rest of `$HOME` is hidden. Paths outside the home directory stay read-only, which is what lets programs execute.
- **Running from `$HOME` is refused.** The working directory is always in scope, so a home-directory launch would expose the whole home.
- **Allowed paths are canonical.** A path whose symlink target is a different location is refused. macOS `/tmp`, `/var`, and `/etc` firmlinks (`/private/...`) are the same path and are accepted.
- **Deny rules win inside the scope.** A denied file stays denied even when it sits in the working directory. Hard links to that file are covered by walking the exposed directories.
- **A project file can only tighten the sandbox.** `.kgate.yaml` may add read and exec denies, and it may shrink the network and path allow lists. It cannot add hosts or paths. One-shot widening is a flag on that invocation (`--allow-path`, `--allow-net`), which comes from the person at the terminal.
- **Network is explicit.** `off` means no egress. `open` means unrestricted egress and is reported as degraded. `restricted` means an allow list of hosts.
- **No sandbox user and no persistent ACLs.** The running process is the invoking user. Group ACLs on the real tree do not confine that user, and the tool does not rewrite permissions on disk.
- **One backend per operating system.** `sandbox-exec` on macOS. `bwrap` on Linux, with `slirp4netns` and iptables when a host allow list has to be enforced. There is no shell-script fallback.

`deny_exec` checks the initial command line and, on Linux, overlays the denied binary path. Copying that binary to a new path, or driving it through an interpreter, is outside that check. Scope and network policy are the boundary. Output masking redacts secrets in the terminal transcript. It is not a kernel control.

Resource limits are left out until they can be enforced. A config key that does nothing is not part of the file format.

## Network on macOS

Checked on macOS 27 (`sandbox-exec` from `/usr/bin/sandbox-exec`).

Seatbelt can hide `$HOME`, allow the working directory, deny a symlink that points at a file outside that directory, and deny writes outside the scope. Those profiles were run on this machine.

The same `sandbox-exec` rejects a network filter whose host is anything other than `*` or `localhost`:

```text
sandbox-exec: host must be * or localhost in network address
```

A per-host allow list cannot be expressed in a Seatbelt profile here. On macOS, `network: restricted` is an error. The enforceable modes are `off` and `open`. Per-host egress belongs to the Linux network namespace, where a missing `slirp4netns` or a name that does not resolve aborts the launch.

## Layout

Global config will live at `~/.kgate/config.yaml`. A project may add `.kgate.yaml`. The audit log will be append-only JSON Lines next to the global config, recording launches and preflight blocks. Kernel denials return `EPERM` with no userspace hook, so they are not pretended into the log.

`KGATE_CONFIG_DIR` overrides the config directory for tests.

## License

Not chosen yet.
