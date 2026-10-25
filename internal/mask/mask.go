package mask

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"kernel_level_gate/internal/policy"
)

// Preset patterns are the token shapes selected by name in mask_stdout.
// Checked against published prefixes in October 2026.
var presetPatterns = map[string]string{
	"openai":     `\bsk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{48}\b`,
	"anthropic":  `\bsk-ant-[A-Za-z0-9_-]{20,}`,
	"aws_key":    `\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b`,
	"aws_secret": `(?i)\baws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`,
	"github":     `\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}`,
	"bearer":     `(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`,
}

const (
	lineHold  = 64 * 1024
	maxSecret = 4096
)

// secretPrefixes are the starts of a preset token. A long line is cut before one of these.
var secretPrefixes = []string{
	"aws_secret_access_key",
	"github_pat_",
	"sk-svcacct-",
	"sk-admin-",
	"sk-proj-",
	"sk-ant-",
	"sk-",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"akia", "asia", "abia", "acca", "a3t",
	"bearer",
}

type rule struct {
	re   *regexp.Regexp
	show int
}

// Set is the compiled redaction rules for one launch.
type Set struct {
	rules []rule
}

// Compile builds a Set. An unknown preset or a bad regular expression is rejected.
func Compile(cfg policy.MaskStdout) (*Set, error) {
	rules := make([]rule, 0, len(cfg.Presets)+len(cfg.Patterns))
	for _, name := range cfg.Presets {
		pattern, ok := presetPatterns[name]
		if !ok {
			return nil, fmt.Errorf("%w: mask preset %q", policy.ErrInvalid, name)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: mask preset %s: %v", policy.ErrInvalid, name, err)
		}
		rules = append(rules, rule{re: re})
	}
	for _, pattern := range cfg.Patterns {
		if pattern.Regex == "" || pattern.ShowPrefix < 0 {
			return nil, fmt.Errorf("%w: mask pattern", policy.ErrInvalid)
		}
		expr := pattern.Regex
		if pattern.CaseInsensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("%w: mask regex: %v", policy.ErrInvalid, err)
		}
		rules = append(rules, rule{re: re, show: pattern.ShowPrefix})
	}
	return &Set{rules: rules}, nil
}

// Apply redacts every complete match in text.
func (s *Set) Apply(text string) string {
	if s == nil || len(s.rules) == 0 || text == "" {
		return text
	}
	type span struct {
		start int
		end   int
		show  int
	}
	var spans []span
	for _, rule := range s.rules {
		for _, loc := range rule.re.FindAllStringIndex(text, -1) {
			spans = append(spans, span{start: loc[0], end: loc[1], show: rule.show})
		}
	}
	slices.SortFunc(spans, func(a, b span) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(b.end, a.end)
	})
	var out strings.Builder
	pos := 0
	for _, sp := range spans {
		if sp.start < pos {
			continue
		}
		out.WriteString(text[pos:sp.start])
		out.WriteString(redact(text[sp.start:sp.end], sp.show))
		pos = sp.end
	}
	out.WriteString(text[pos:])
	return out.String()
}

func redact(match string, show int) string {
	if show < 0 || show > len(match) {
		show = 0
	}
	if show == 0 || show == len(match) {
		return "***"
	}
	return match[:show] + "***"
}

// Writer masks dst. A secret split across writes is held until the line ends.
type Writer struct {
	dst io.Writer
	set *Set
	buf []byte
}

// NewWriter compiles cfg and writes masked output to dst.
func NewWriter(dst io.Writer, cfg policy.MaskStdout) (*Writer, error) {
	set, err := Compile(cfg)
	if err != nil {
		return nil, err
	}
	return &Writer{dst: dst, set: set}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		ready, rest := takeReady(w.buf)
		if len(ready) == 0 {
			return len(p), nil
		}
		if _, err := w.dst.Write([]byte(w.set.Apply(string(ready)))); err != nil {
			return len(p), err
		}
		w.buf = rest
	}
}

// Flush masks the unfinished tail and writes it.
func (w *Writer) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	out := []byte(w.set.Apply(string(w.buf)))
	w.buf = nil
	_, err := w.dst.Write(out)
	return err
}

func takeReady(buf []byte) (ready, rest []byte) {
	if i := lastBreak(buf); i >= 0 {
		return buf[:i+1], append([]byte(nil), buf[i+1:]...)
	}
	if len(buf) <= lineHold {
		return nil, buf
	}
	cut := len(buf) - maxSecret
	if cut <= 0 {
		return nil, buf
	}
	if next := rewindPrefix(buf, cut); next > 0 {
		cut = next
	}
	return buf[:cut], append([]byte(nil), buf[cut:]...)
}

func lastBreak(buf []byte) int {
	n := bytes.LastIndexByte(buf, '\n')
	r := bytes.LastIndexByte(buf, '\r')
	if r > n {
		return r
	}
	return n
}

func rewindPrefix(buf []byte, cut int) int {
	start := cut - maxSecret
	if start < 0 {
		start = 0
	}
	best := cut
	region := bytes.ToLower(buf[start:cut])
	for _, prefix := range secretPrefixes {
		needle := []byte(strings.ToLower(prefix))
		off := 0
		for off < len(region) {
			rel := bytes.Index(region[off:], needle)
			if rel < 0 {
				break
			}
			abs := start + off + rel
			if abs < best && secretOpen(buf, abs, cut, prefix) {
				best = abs
			}
			off += rel + 1
		}
	}
	return best
}

func secretOpen(buf []byte, abs, cut int, prefix string) bool {
	i := abs + len(prefix)
	if i > cut {
		return true
	}
	switch strings.ToLower(prefix) {
	case "bearer":
		for i < cut && (buf[i] == ' ' || buf[i] == '\t') {
			i++
		}
	case "aws_secret_access_key":
		for i < cut && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '=' || buf[i] == ':') {
			i++
		}
	}
	for ; i < cut; i++ {
		if !isSecretByte(buf[i]) {
			return false
		}
	}
	return true
}

func isSecretByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_' || b == '-' || b == '.' || b == '/' || b == '+' || b == '=' || b == '~':
		return true
	default:
		return false
	}
}
