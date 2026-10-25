package policy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// CheckCommand rejects an argv that runs a denied command.
// Shells must be a checked -c script. Interpreter text and copies of a denied binary are checked too.
func CheckCommand(argv, deny []string) error {
	if len(argv) == 0 || len(deny) == 0 {
		return nil
	}
	return checkArgv(argv, deny, deniedFiles(deny), 0)
}

func checkArgv(argv, deny []string, ids []fileID, depth int) error {
	if depth > 8 {
		return fmt.Errorf("%w: command is too nested to check", ErrBlocked)
	}
	argv = unwrap(argv)
	if len(argv) == 0 {
		return nil
	}
	if path := commandPath(argv[0]); path != "" && fileMatch(path, ids) {
		return fmt.Errorf("%w: %s", ErrBlocked, argv[0])
	}
	if rule := deniedBy(argv, deny); rule != "" {
		return fmt.Errorf("%w: %s", ErrBlocked, rule)
	}
	base := filepath.Base(argv[0])
	switch base {
	case "eval":
		return fmt.Errorf("%w: eval cannot be checked", ErrBlocked)
	case "source", ".":
		return checkSource(argv, deny, ids, depth)
	}
	if isCopier(base) {
		if err := checkCopier(argv, deny, ids); err != nil {
			return err
		}
	}
	if isShell(argv[0]) {
		if len(argv) == 1 {
			return fmt.Errorf("%w: shell invocation cannot be checked", ErrBlocked)
		}
		script, ok, err := shellScript(argv)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: shell invocation cannot be checked", ErrBlocked)
		}
		return checkScript(script, deny, ids, depth+1)
	}
	if isInterpreter(base) {
		return checkInterpreter(argv, deny)
	}
	return nil
}

func checkScript(script string, deny []string, ids []fileID, depth int) error {
	subs, err := substitutions(script)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if err := checkScript(sub, deny, ids, depth+1); err != nil {
			return err
		}
	}
	parts, err := segments(script)
	if err != nil {
		return err
	}
	for _, part := range parts {
		argv, err := words(part)
		if err != nil {
			return err
		}
		if len(argv) == 0 {
			continue
		}
		if err := checkArgv(argv, deny, ids, depth+1); err != nil {
			return err
		}
	}
	return nil
}

type flagSpec struct {
	short string
	long  []string
}

var wrappers = map[string]flagSpec{
	// sudo runs another command, possibly as a different user.
	"sudo": {short: "ugphCTrtU", long: []string{"user", "group", "host", "prompt", "role", "type", "other-user", "close-from", "chdir", "command-timeout"}},
	// env sets variables, then runs the command.
	"env": {short: "uSC", long: []string{"unset", "split-string", "chdir", "argv0", "default-signal", "ignore-signal", "block-signal"}},
	// nice runs a command at a changed scheduling priority.
	"nice": {short: "n", long: []string{"adjustment"}},
	// time runs a command and reports how long it took.
	"time": {short: "of", long: []string{"output", "format", "append"}},
	// exec replaces this process with the command.
	"exec": {short: "a", long: []string{"argv0"}},
	// nohup runs a command so it keeps going after hangup.
	"nohup": {},
	// command runs a program instead of a shell function with the same name.
	"command": {},
}

func unwrap(argv []string) []string {
	for len(argv) > 0 {
		if isAssign(argv[0]) {
			argv = argv[1:]
			continue
		}
		spec, ok := wrappers[filepath.Base(argv[0])]
		if !ok {
			return argv
		}
		argv = skipFlags(argv[1:], spec)
	}
	return argv
}

func skipFlags(argv []string, spec flagSpec) []string {
	for len(argv) > 0 && strings.HasPrefix(argv[0], "-") && argv[0] != "-" {
		tok := argv[0]
		argv = argv[1:]
		if tok == "--" {
			break
		}
		if name, ok := strings.CutPrefix(tok, "--"); ok {
			name, _, attached := strings.Cut(name, "=")
			if !attached && slices.Contains(spec.long, name) && len(argv) > 0 {
				argv = argv[1:]
			}
			continue
		}
		letters := tok[1:]
		takesArg := false
		for _, r := range letters {
			if strings.ContainsRune(spec.short, r) {
				takesArg = true
			}
		}
		if takesArg && len(letters) == 1 && len(argv) > 0 {
			argv = argv[1:]
		}
	}
	return argv
}

func isAssign(tok string) bool {
	name, _, ok := strings.Cut(tok, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func isShell(name string) bool {
	switch filepath.Base(name) {
	case "sh", "bash", "zsh", "dash":
		return true
	default:
		return false
	}
}

func shellScript(argv []string) (string, bool, error) {
	for i := 1; i < len(argv); i++ {
		if argv[i] != "-c" {
			continue
		}
		if i+1 >= len(argv) {
			return "", false, fmt.Errorf("%w: shell -c is missing a script", ErrInvalid)
		}
		return argv[i+1], true, nil
	}
	return "", false, nil
}

func deniedBy(argv, deny []string) string {
	base := filepath.Base(argv[0])
	for _, rule := range deny {
		fields := strings.Fields(rule)
		if len(fields) == 0 || len(fields) > len(argv) || fields[0] != base {
			continue
		}
		match := true
		for i := 1; i < len(fields); i++ {
			if argv[i] != fields[i] {
				match = false
				break
			}
		}
		if match {
			return rule
		}
	}
	return ""
}

func segments(script string) ([]string, error) {
	var parts []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(script); i++ {
		c := script[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			} else if quote == '"' && c == '\\' && i+1 < len(script) {
				i++
				b.WriteByte(script[i])
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '\\' && i+1 < len(script) {
			b.WriteByte(script[i+1])
			i++
			continue
		}
		if c == ';' || c == '|' || c == '&' || c == '\n' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: unclosed quote", ErrInvalid)
	}
	parts = append(parts, b.String())
	return parts, nil
}

func substitutions(script string) ([]string, error) {
	var out []string
	quote := byte(0)
	for i := 0; i < len(script); i++ {
		c := script[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' && c == '\\' && i+1 < len(script) {
			i++
			continue
		}
		if quote == '"' && c == '"' {
			quote = 0
			continue
		}
		if quote == 0 && (c == '\'' || c == '"') {
			quote = c
			continue
		}
		if quote == 0 && c == '\\' && i+1 < len(script) {
			i++
			continue
		}
		if c == '`' {
			j := strings.IndexByte(script[i+1:], '`')
			if j < 0 {
				return nil, fmt.Errorf("%w: unclosed command substitution", ErrInvalid)
			}
			out = append(out, script[i+1:i+1+j])
			i += 1 + j
			continue
		}
		if c == '$' && i+1 < len(script) && script[i+1] == '(' {
			inner, next, err := takeCall(script, i+2)
			if err != nil {
				return nil, err
			}
			out = append(out, inner)
			i = next - 1
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: unclosed quote", ErrInvalid)
	}
	return out, nil
}

func takeCall(script string, start int) (string, int, error) {
	depth := 1
	quote := byte(0)
	for i := start; i < len(script); i++ {
		c := script[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' && c == '\\' && i+1 < len(script) {
			i++
			continue
		}
		if c == '"' && quote == '"' {
			quote = 0
			continue
		}
		if quote == 0 && (c == '\'' || c == '"') {
			quote = c
			continue
		}
		if quote != 0 {
			continue
		}
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			depth--
			if depth == 0 {
				return script[start:i], i + 1, nil
			}
		}
	}
	return "", 0, fmt.Errorf("%w: unclosed command substitution", ErrInvalid)
}

func words(seg string) ([]string, error) {
	var out []string
	for i := 0; i < len(seg); {
		for i < len(seg) && (seg[i] == ' ' || seg[i] == '\t') {
			i++
		}
		if i >= len(seg) || seg[i] == '>' || seg[i] == '<' {
			break
		}
		tok, next, err := word(seg, i)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			out = append(out, tok)
		}
		i = next
	}
	return out, nil
}

func word(s string, i int) (string, int, error) {
	var b strings.Builder
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '>' || c == '<' || c == ';' || c == '|' || c == '&' || c == '\n' {
			break
		}
		if c == '\'' {
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", 0, fmt.Errorf("%w: unclosed quote", ErrInvalid)
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
			continue
		}
		if c == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return "", 0, fmt.Errorf("%w: unclosed quote", ErrInvalid)
			}
			i++
			continue
		}
		if c == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i, nil
}

type fileID struct {
	info os.FileInfo
	size int64
	sum  []byte
}

func deniedFiles(deny []string) []fileID {
	var out []fileID
	seen := map[string]bool{}
	for _, rule := range deny {
		fields := strings.Fields(rule)
		if len(fields) != 1 || seen[fields[0]] {
			continue
		}
		seen[fields[0]] = true
		path := fields[0]
		if !strings.Contains(path, "/") {
			found, err := exec.LookPath(path)
			if err != nil {
				continue
			}
			path = found
		}
		id, err := identify(path)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out
}

func identify(path string) (fileID, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileID{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fileID{}, err
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return fileID{}, err
	}
	return fileID{info: info, size: info.Size(), sum: sum.Sum(nil)}, nil
}

func commandPath(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

func fileMatch(path string, ids []fileID) bool {
	if len(ids) == 0 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return true
	}
	sameSize := false
	for _, id := range ids {
		if os.SameFile(info, id.info) {
			return true
		}
		if id.size == info.Size() {
			sameSize = true
		}
	}
	if !sameSize {
		return false
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return true
	}
	got := sum.Sum(nil)
	for _, id := range ids {
		if id.size == info.Size() && bytes.Equal(got, id.sum) {
			return true
		}
	}
	return false
}

func isCopier(base string) bool {
	switch base {
	case "cp", "mv", "install", "ln", "link", "ditto", "dd", "cat", "tee":
		return true
	default:
		return false
	}
}

func checkCopier(argv, deny []string, ids []fileID) error {
	for _, arg := range argv[1:] {
		if arg == "--" || (strings.HasPrefix(arg, "-") && arg != "-") {
			continue
		}
		path := arg
		if _, value, ok := strings.Cut(arg, "="); ok {
			path = value
		}
		if path == "" {
			continue
		}
		if fileMatch(path, ids) || deniedBy([]string{filepath.Base(path)}, deny) != "" {
			return fmt.Errorf("%w: %s", ErrBlocked, path)
		}
	}
	return nil
}

func checkSource(argv, deny []string, ids []fileID, depth int) error {
	if len(argv) < 2 {
		return fmt.Errorf("%w: source file is missing", ErrBlocked)
	}
	body, err := os.ReadFile(argv[1])
	if err != nil {
		return fmt.Errorf("%w: cannot read source file", ErrBlocked)
	}
	return checkScript(string(body), deny, ids, depth+1)
}

func isInterpreter(base string) bool {
	switch base {
	case "perl", "ruby", "node", "nodejs", "php", "lua", "osascript", "deno", "bun":
		return true
	default:
		return isPython(base)
	}
}

func isPython(base string) bool {
	if base == "python" || base == "python2" || base == "python3" {
		return true
	}
	rest, ok := strings.CutPrefix(base, "python")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func checkInterpreter(argv, deny []string) error {
	base := filepath.Base(argv[0])
	saw := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "-i" || arg == "--interactive" {
			return fmt.Errorf("%w: interactive interpreter cannot be checked", ErrBlocked)
		}
		if arg == "--" {
			for _, path := range argv[i+1:] {
				if err := scanFile(path, deny); err != nil {
					return err
				}
				saw = true
			}
			break
		}
		if codeFlag(base, arg) {
			if i+1 >= len(argv) {
				return fmt.Errorf("%w: interpreter code is missing", ErrInvalid)
			}
			i++
			if err := scanText(argv[i], deny); err != nil {
				return err
			}
			saw = true
			continue
		}
		if consumesArg(base, arg) {
			if i+1 >= len(argv) {
				return fmt.Errorf("%w: interpreter argument is missing", ErrInvalid)
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if err := scanFile(arg, deny); err != nil {
			return err
		}
		saw = true
	}
	if !saw {
		return fmt.Errorf("%w: interactive interpreter cannot be checked", ErrBlocked)
	}
	return nil
}

func codeFlag(base, arg string) bool {
	switch {
	case isPython(base):
		return arg == "-c"
	case base == "perl" || base == "ruby" || base == "lua" || base == "osascript":
		return arg == "-e"
	case base == "node" || base == "nodejs" || base == "bun":
		return arg == "-e" || arg == "--eval"
	case base == "php":
		return arg == "-r"
	case base == "deno" && arg == "eval":
		return true
	default:
		return false
	}
}

func consumesArg(base, arg string) bool {
	if isPython(base) {
		return arg == "-m" || arg == "-W" || arg == "-X"
	}
	return false
}

func scanFile(path string, deny []string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: cannot read interpreter script", ErrBlocked)
	}
	return scanText(string(body), deny)
}

func scanText(text string, deny []string) error {
	toks := tokens(text)
	for _, rule := range deny {
		fields := strings.Fields(rule)
		if len(fields) == 0 {
			continue
		}
		for i := 0; i+len(fields) <= len(toks); i++ {
			if filepath.Base(toks[i]) != fields[0] {
				continue
			}
			match := true
			for j := 1; j < len(fields); j++ {
				if toks[i+j] != fields[j] {
					match = false
					break
				}
			}
			if match {
				return fmt.Errorf("%w: %s", ErrBlocked, rule)
			}
		}
	}
	return nil
}

func tokens(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}
	for _, r := range text {
		if isToken(r) {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

func isToken(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '_' || r == '.' || r == '-' || r == '/':
		return true
	default:
		return false
	}
}
