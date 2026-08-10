package zucchini

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateFileRawRoundTrip(t *testing.T) {
	dir := t.TempDir()
	oldImage := []byte("mapped old image contents")
	newImage := []byte("mapped new image contents with a suffix")
	oldPath := filepath.Join(dir, "old.bin")
	newPath := filepath.Join(dir, "new.bin")
	patchPath := filepath.Join(dir, "update.patch")
	outputPath := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(oldPath, oldImage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, newImage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateFileWithOptions(oldPath, newPath, patchPath, GenerateFileOptions{Raw: true}); err != nil {
		t.Fatalf("GenerateFileWithOptions: %v", err)
	}
	if err := ApplyFile(oldPath, patchPath, outputPath); err != nil {
		t.Fatalf("ApplyFile: %v", err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newImage) {
		t.Fatalf("applied image = %q, want %q", got, newImage)
	}
}

func TestFileAPIsRejectOutputInputCollision(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.bin")
	newPath := filepath.Join(dir, "new.bin")
	if err := os.WriteFile(oldPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateFile(oldPath, newPath, oldPath); err == nil {
		t.Fatal("GenerateFile unexpectedly allowed output to overwrite an input")
	}
	got, err := os.ReadFile(oldPath)
	if err != nil || string(got) != "old" {
		t.Fatalf("old input was modified: %q, %v", got, err)
	}
}

func TestApplyFilePartialOutputLifecycle(t *testing.T) {
	oldImage := []byte("the old image")
	newImage := []byte("the new image")
	patchBytes, err := GenerateBuffer(oldImage, newImage)
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}
	// Keep the patch structurally valid but force final output verification to
	// fail after the output file has been created and populated.
	binary.LittleEndian.PutUint32(patchBytes[20:24], 0)

	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.bin")
	patchPath := filepath.Join(dir, "patch.bin")
	if err := os.WriteFile(oldPath, oldImage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, patchBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	removedPath := filepath.Join(dir, "removed.bin")
	if err := ApplyFileWithOptions(oldPath, patchPath, removedPath, ApplyFileOptions{}); err == nil {
		t.Fatal("ApplyFileWithOptions unexpectedly succeeded")
	}
	if _, err := os.Stat(removedPath); !os.IsNotExist(err) {
		t.Fatalf("partial output was not removed: %v", err)
	}

	keptPath := filepath.Join(dir, "kept.bin")
	if err := ApplyFileWithOptions(oldPath, patchPath, keptPath, ApplyFileOptions{KeepPartialOutput: true}); err == nil {
		t.Fatal("ApplyFileWithOptions unexpectedly succeeded")
	}
	info, err := os.Stat(keptPath)
	if err != nil {
		t.Fatalf("partial output was not retained: %v", err)
	}
	if info.Size() != int64(len(newImage)) {
		t.Fatalf("partial output size = %d, want %d", info.Size(), len(newImage))
	}
}
