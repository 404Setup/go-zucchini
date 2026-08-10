package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/404Setup/go-zucchini"
)

func TestParseCommandLineValid(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		command    string
		positional []string
		flags      []string
		values     map[string]string
	}{
		{"legacy command", []string{"-gen", "old", "new", "patch", "-raw", "--keep"}, "gen", []string{"old", "new", "patch"}, []string{"raw", "keep"}, nil},
		{"legacy command after arguments", []string{"old", "new", "-gen", "patch", "--raw"}, "gen", []string{"old", "new", "patch"}, []string{"raw"}, nil},
		{"conventional command", []string{"gen", "old", "new", "patch", "--impose=0+4=0+4"}, "gen", []string{"old", "new", "patch"}, []string{"impose"}, map[string]string{"impose": "0+4=0+4"}},
		{"trusted apply digest", []string{"apply", "old", "patch", "new", "--sha256", strings.Repeat("ab", 32)}, "apply", []string{"old", "patch", "new"}, []string{"sha256"}, map[string]string{"sha256": strings.Repeat("ab", 32)}},
		{"separate value", []string{"match", "old", "new", "--impose", "0+4=0+4"}, "match", []string{"old", "new"}, []string{"impose"}, map[string]string{"impose": "0+4=0+4"}},
		{"underscore alias", []string{"suffix_array", "file"}, "suffix-array", []string{"file"}, nil, nil},
		{"option terminator", []string{"read", "--", "-executable"}, "read", []string{"-executable"}, nil, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parseCommandLine(test.args)
			if err != nil {
				t.Fatalf("parseCommandLine() error: %v", err)
			}
			if parsed.spec.name != test.command {
				t.Fatalf("command = %q, want %q", parsed.spec.name, test.command)
			}
			if strings.Join(parsed.positional, "\x00") != strings.Join(test.positional, "\x00") {
				t.Fatalf("positional = %q, want %q", parsed.positional, test.positional)
			}
			for _, flag := range test.flags {
				if !parsed.has(flag) {
					t.Errorf("flag %q was not set", flag)
				}
			}
			for name, want := range test.values {
				if got := parsed.value(name); got != want {
					t.Errorf("value(%q) = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestParseCommandLineRejectsInvalidInput(t *testing.T) {
	tests := map[string][]string{
		"missing command":       nil,
		"unknown command":       {"unknown"},
		"missing argument":      {"gen", "old", "new"},
		"extra argument":        {"verify", "patch", "extra"},
		"unknown option":        {"apply", "old", "patch", "new", "--raw"},
		"duplicate option":      {"read", "file", "--dump", "-dump"},
		"missing option value":  {"match", "old", "new", "--impose"},
		"empty option value":    {"match", "old", "new", "--impose="},
		"boolean option value":  {"read", "file", "--dump=true"},
		"conflicting options":   {"gen", "old", "new", "patch", "--raw", "--impose=0+1=0+1"},
		"second command switch": {"-gen", "old", "new", "patch", "-apply"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCommandLine(args); err == nil {
				t.Fatal("parseCommandLine() unexpectedly succeeded")
			}
		})
	}
}

func TestRunCLIHelpVersionAndCRC32(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--help"}, &stdout, &stderr); code != zucchini.StatusSuccess || !strings.Contains(stdout.String(), "Commands:") {
		t.Fatalf("help: code=%v stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"version"}, &stdout, &stderr); code != zucchini.StatusSuccess || strings.TrimSpace(stdout.String()) != "Zucchini 2.0" {
		t.Fatalf("version: code=%v stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	file := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(file, []byte("123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"crc32", file}, &stdout, &stderr); code != zucchini.StatusSuccess || strings.TrimSpace(stdout.String()) != "CRC32: CBF43926" {
		t.Fatalf("crc32: code=%v stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCLIRejectsOutputInputCollision(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.bin")
	newPath := filepath.Join(dir, "new.bin")
	if err := os.WriteFile(oldPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"gen", oldPath, newPath, oldPath}, &stdout, &stderr); code != zucchini.StatusInvalidParam {
		t.Fatalf("runCLI() = %v, want %v", code, zucchini.StatusInvalidParam)
	}
	got, err := os.ReadFile(oldPath)
	if err != nil || string(got) != "old" {
		t.Fatalf("old input was modified: %q, %v", got, err)
	}
}

func TestRunCLIRejectsInvalidSHA256(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"apply", "old", "patch", "new", "--sha256", "not-a-digest"}, &stdout, &stderr)
	if code != zucchini.StatusInvalidParam || !strings.Contains(stderr.String(), "64 hexadecimal") {
		t.Fatalf("runCLI() = %v, stderr=%q", code, stderr.String())
	}
}
