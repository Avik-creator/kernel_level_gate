package mask

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"kernel_level_gate/internal/policy"
)

func TestMaskPresets(t *testing.T) {
	set, err := Compile(policy.MaskStdout{Presets: []string{
		"openai", "anthropic", "aws_key", "aws_secret", "github", "bearer",
	}})
	if err != nil {
		t.Fatal(err)
	}
	secret := "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	cases := []string{
		"sk-proj-" + strings.Repeat("a", 40),
		"sk-ant-api03-" + strings.Repeat("b", 40),
		"AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key=" + secret,
		"ghp_" + strings.Repeat("c", 36),
		"Bearer abcdef.ghijkl",
	}
	for _, token := range cases {
		got := set.Apply("see " + token + " now")
		if strings.Contains(got, token) {
			t.Fatalf("left %q in %q", token, got)
		}
		if !strings.Contains(got, "***") {
			t.Fatalf("no mask in %q", got)
		}
	}
	if got := set.Apply("sk-proj-short"); got != "sk-proj-short" {
		t.Fatalf("masked a short token: %q", got)
	}
}

func TestMaskShowPrefixAndCase(t *testing.T) {
	set, err := Compile(policy.MaskStdout{Patterns: []policy.MaskPattern{{
		Regex:           `secret=\S+`,
		ShowPrefix:      7,
		CaseInsensitive: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got := set.Apply("Secret=hunter2")
	if strings.Contains(got, "hunter2") {
		t.Fatalf("value leaked: %q", got)
	}
	if !strings.Contains(got, "Secret=***") {
		t.Fatalf("prefix not kept: %q", got)
	}
}

func TestMaskRejectsUnknownPreset(t *testing.T) {
	_, err := Compile(policy.MaskStdout{Presets: []string{"nope"}})
	if !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestMaskAWSSecretPadding(t *testing.T) {
	set, err := Compile(policy.MaskStdout{Presets: []string{"aws_secret"}})
	if err != nil {
		t.Fatal(err)
	}
	token := "aws_secret_access_key=" + strings.Repeat("a", 39) + "="
	got := set.Apply("see " + token + " now")
	if strings.Contains(got, strings.Repeat("a", 39)) {
		t.Fatalf("left the secret in %q", got)
	}
}

func TestMaskLongLineKeepsTheTokenWhole(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, policy.MaskStdout{Presets: []string{"openai"}})
	if err != nil {
		t.Fatal(err)
	}
	token := "sk-proj-" + strings.Repeat("b", 40)
	total := lineHold + maxSecret
	cut := total - maxSecret
	start := cut - 10
	raw := make([]byte, total)
	for i := range raw {
		raw[i] = 'x'
	}
	copy(raw[start:], token)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("sk-proj-")) {
		t.Fatal("emitted part of a token")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(token)) {
		t.Fatal("secret leaked after flush")
	}
}

func TestMaskHoldsASplitSecret(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, policy.MaskStdout{Presets: []string{"openai"}})
	if err != nil {
		t.Fatal(err)
	}
	token := "sk-proj-" + strings.Repeat("a", 40)
	if _, err := w.Write([]byte("token " + token[:12])); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("sk-proj-")) {
		t.Fatalf("emitted a partial secret: %q", buf.String())
	}
	if _, err := w.Write([]byte(token[12:] + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(token)) {
		t.Fatalf("secret leaked: %q", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("***")) {
		t.Fatalf("no mask in %q", buf.String())
	}
}
