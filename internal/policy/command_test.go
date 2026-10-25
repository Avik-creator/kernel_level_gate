package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCommand(t *testing.T) {
	deny := []string{"curl", "kubectl delete"}
	cases := []struct {
		name string
		argv []string
		want error
	}{
		{name: "curl", argv: []string{"curl", "https://example"}, want: ErrBlocked},
		{name: "curl path", argv: []string{"/usr/bin/curl"}, want: ErrBlocked},
		{name: "other binary", argv: []string{"wget"}, want: nil},
		{name: "kubectl delete", argv: []string{"kubectl", "delete", "pod"}, want: ErrBlocked},
		{name: "kubectl get", argv: []string{"kubectl", "get", "pod"}, want: nil},
		{name: "sudo", argv: []string{"sudo", "curl"}, want: ErrBlocked},
		{name: "sudo user", argv: []string{"sudo", "-u", "root", "curl"}, want: ErrBlocked},
		{name: "env assignment", argv: []string{"env", "FOO=1", "curl"}, want: ErrBlocked},
		{name: "nice", argv: []string{"nice", "-n", "5", "curl"}, want: ErrBlocked},
		{name: "shell separator", argv: []string{"bash", "-c", "echo ok; curl x"}, want: ErrBlocked},
		{name: "pipeline", argv: []string{"bash", "-c", "echo ok | curl x"}, want: ErrBlocked},
		{name: "and", argv: []string{"bash", "-c", "echo ok && curl x"}, want: ErrBlocked},
		{name: "quoted separator", argv: []string{"bash", "-c", "echo 'ok; curl x'"}, want: nil},
		{name: "substitution", argv: []string{"bash", "-c", "echo $(curl x)"}, want: ErrBlocked},
		{name: "single quotes", argv: []string{"bash", "-c", "echo '$(curl x)'"}, want: nil},
		{name: "double quotes", argv: []string{"bash", "-c", "echo \"$(curl x)\""}, want: ErrBlocked},
		{name: "backtick", argv: []string{"bash", "-c", "echo `curl x`"}, want: ErrBlocked},
		{name: "plain shell", argv: []string{"bash"}, want: ErrBlocked},
		{name: "nested shell", argv: []string{"bash", "-c", "bash"}, want: ErrBlocked},
		{name: "eval", argv: []string{"bash", "-c", "eval curl"}, want: ErrBlocked},
		{name: "python repl", argv: []string{"python"}, want: ErrBlocked},
		{name: "python print", argv: []string{"python", "-c", "print(1)"}, want: nil},
		{name: "python system", argv: []string{"python", "-c", `os.system("curl")`}, want: ErrBlocked},
		{name: "kubectl get text", argv: []string{"python", "-c", `print("kubectl get")`}, want: nil},
		{name: "kubectl delete text", argv: []string{"python", "-c", `print("kubectl delete")`}, want: ErrBlocked},
		{name: "clustered shell flag", argv: []string{"bash", "-lc", "curl x"}, want: ErrBlocked},
		{name: "allowed script", argv: []string{"sh", "-c", "echo ok"}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckCommand(tc.argv, deny)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCheckCommandMissingScript(t *testing.T) {
	err := CheckCommand([]string{"bash", "-c"}, []string{"curl"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestCheckCommandEmptyDeny(t *testing.T) {
	if err := CheckCommand([]string{"curl"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCommandCopyAndScript(t *testing.T) {
	dir := t.TempDir()
	body := []byte("#!/bin/sh\necho hi\n")
	curl := filepath.Join(dir, "curl")
	if err := os.WriteFile(curl, body, 0o755); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "notcurl")
	if err := os.WriteFile(copyPath, body, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(curl, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	deny := []string{"curl"}
	if err := CheckCommand([]string{copyPath}, deny); !errors.Is(err, ErrBlocked) {
		t.Fatalf("copy: got %v, want ErrBlocked", err)
	}
	if err := CheckCommand([]string{link}, deny); !errors.Is(err, ErrBlocked) {
		t.Fatalf("symlink: got %v, want ErrBlocked", err)
	}
	if err := CheckCommand([]string{"cp", curl, filepath.Join(dir, "other")}, deny); !errors.Is(err, ErrBlocked) {
		t.Fatalf("cp: got %v, want ErrBlocked", err)
	}

	script := filepath.Join(dir, "ok.py")
	if err := os.WriteFile(script, []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckCommand([]string{"python", script}, deny); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.py")
	if err := os.WriteFile(bad, []byte("os.system('curl')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckCommand([]string{"python", bad}, deny); !errors.Is(err, ErrBlocked) {
		t.Fatalf("script: got %v, want ErrBlocked", err)
	}
}
