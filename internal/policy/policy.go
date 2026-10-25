package policy

import "errors"

// Network is the egress policy.
// off has no egress, open is unrestricted, restricted allows only AllowNet.
type Network string

const (
	NetworkOff        Network = "off"
	NetworkRestricted Network = "restricted"
	NetworkOpen       Network = "open"
)

// Valid reports whether n is one of the three known modes.
func (n Network) Valid() bool {
	switch n {
	case NetworkOff, NetworkRestricted, NetworkOpen:
		return true
	default:
		return false
	}
}

// Openness ranks modes so a project file can only move to a stricter one.
func Openness(n Network) int {
	switch n {
	case NetworkOff:
		return 0
	case NetworkRestricted:
		return 1
	case NetworkOpen:
		return 2
	default:
		return 3
	}
}

// MaskPattern is one user-supplied redaction rule.
// Masking edits the terminal transcript. It is not a kernel control.
type MaskPattern struct {
	Regex           string `yaml:"regex"`
	ShowPrefix      int    `yaml:"show_prefix,omitempty"`
	CaseInsensitive bool   `yaml:"case_insensitive,omitempty"`
}

// MaskStdout is the set of transcript redaction rules.
type MaskStdout struct {
	Presets  []string      `yaml:"presets,omitempty"`
	Patterns []MaskPattern `yaml:"patterns,omitempty"`
}

// Config is the on-disk policy.
// Scope is always on at launch. AllowedPaths only adds locations beside the working directory.
type Config struct {
	Network      Network    `yaml:"network"`
	AllowNet     []string   `yaml:"allow_net,omitempty"`
	AllowedPaths []string   `yaml:"allowed_paths,omitempty"`
	DenyRead     []string   `yaml:"deny_read,omitempty"`
	DenyExec     []string   `yaml:"deny_exec,omitempty"`
	MaskStdout   MaskStdout `yaml:"mask_stdout,omitempty"`
}

// Overlay is a project .kgate.yaml.
// A nil pointer means the key was absent, so it does not clear the global value.
type Overlay struct {
	Network      *Network    `yaml:"network"`
	AllowNet     *[]string   `yaml:"allow_net"`
	AllowedPaths *[]string   `yaml:"allowed_paths"`
	DenyRead     *[]string   `yaml:"deny_read"`
	DenyExec     *[]string   `yaml:"deny_exec"`
	MaskStdout   *MaskStdout `yaml:"mask_stdout"`
}

var (
	ErrNotInitialized = errors.New("kgate is not initialized")
	ErrWiden          = errors.New("refusing to widen the sandbox")
	ErrBlocked        = errors.New("command blocked by policy")
	ErrScope          = errors.New("filesystem scope cannot be enforced")
	ErrSymlink        = errors.New("path is a symlink to a different location")
	ErrNetwork        = errors.New("network policy cannot be enforced on this OS")
	ErrUnsupported    = errors.New("unsupported operating system")
	ErrInvalid        = errors.New("invalid configuration")
)

// Default is the global policy written by kgate init.
func Default() Config {
	return Config{
		Network: NetworkRestricted,
		AllowNet: []string{
			"api.anthropic.com",
			"api.openai.com",
			"api.github.com",
			"registry.npmjs.org",
			"proxy.golang.org",
		},
		AllowedPaths: []string{
			"~/.cache",
			"~/.config",
			"~/.local",
			"~/.claude",
			"~/.claude.json",
			"~/.npm",
		},
		DenyRead: []string{
			".env",
			".env.*",
			"secrets",
			"credentials",
			"~/.ssh",
			"*.pem",
			"*.key",
			"*.p12",
			"~/.aws",
			"~/.gcloud",
			"~/.kube/config",
			"~/.npmrc",
			"~/.pypirc",
			"terraform.tfstate",
			"*.tfvars",
		},
		DenyExec: []string{
			"curl",
			"wget",
			"nc",
			"ncat",
			"netcat",
			"ssh",
			"scp",
			"rsync",
			"ftp",
			"kubectl delete",
			"kubectl exec",
		},
		MaskStdout: MaskStdout{
			Presets: []string{"openai", "anthropic", "aws_key", "aws_secret", "github", "bearer"},
			Patterns: []MaskPattern{{
				Regex:           `(?:api_?key|secret|password|passwd|token|credential)\s*[=:]\s*\S+`,
				CaseInsensitive: true,
			}},
		},
	}
}
