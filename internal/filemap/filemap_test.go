package filemap

import (
	"bytes"
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
