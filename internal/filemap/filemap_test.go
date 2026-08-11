package filemap

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMappingRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	outputPath := filepath.Join(tempDir, "output.bin")
	emptyPath := filepath.Join(tempDir, "empty.bin")
	want := []byte("mapped zucchini data")
	if err := os.WriteFile(inputPath, want, 0o644); err != nil {
		t.Fatal(err)
	}

	input, err := Open(inputPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(input.Data, want) {
		t.Fatalf("mapped input = %q, want %q", input.Data, want)
	}
	if err := input.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}

	output, err := Create(outputPath, len(want))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	copy(output.Data, want)
	if err := output.Close(); err != nil {
		t.Fatalf("close output: %v", err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("mapped output = %q, want %q", got, want)
	}

	empty, err := Create(emptyPath, 0)
	if err != nil {
		t.Fatalf("Create empty: %v", err)
	}
	if len(empty.Data) != 0 {
		t.Fatalf("empty mapping length = %d", len(empty.Data))
	}
	if err := empty.Close(); err != nil {
		t.Fatalf("close empty: %v", err)
	}
	empty, err = Open(emptyPath)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatalf("close empty input: %v", err)
	}
}

func TestMappingRejectsInvalidInputs(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open(missing) error = %v, want os.ErrNotExist", err)
	}
	if _, err := CreateFromFile(nil, 1); err == nil {
		t.Fatal("CreateFromFile(nil) unexpectedly succeeded")
	}
	file, err := os.CreateTemp(t.TempDir(), "mapping-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := CreateFromFile(file, -1); err == nil {
		t.Fatal("CreateFromFile accepted a negative size")
	}

	var nilMapping *Mapping
	if err := nilMapping.Close(); err != nil {
		t.Fatalf("nil Mapping.Close() = %v", err)
	}
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !SameFile(path, filepath.Join(dir, ".", "data.bin")) {
		t.Fatal("equivalent existing paths were not recognized")
	}
	missing := filepath.Join(dir, "missing.bin")
	if !SameFile(missing, filepath.Join(dir, "subdir", "..", "missing.bin")) {
		t.Fatal("equivalent missing paths were not recognized")
	}
	if SameFile(path, missing) {
		t.Fatal("different paths were reported as the same file")
	}
}
