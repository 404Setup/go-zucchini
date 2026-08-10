package zucchini

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileAPIs(t *testing.T) {
	tempDir := t.TempDir()
	oldData := []byte("The quick brown fox jumps over the lazy dog. File-backed zucchini input.")
	newData := []byte("The quick green fox jumps over the very lazy dog! File-backed zucchini output.")
	oldPath := filepath.Join(tempDir, "old.bin")
	newPath := filepath.Join(tempDir, "new.bin")
	patchPath := filepath.Join(tempDir, "update.patch")
	appliedPath := filepath.Join(tempDir, "applied.bin")
	if err := os.WriteFile(oldPath, oldData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, newData, 0o644); err != nil {
		t.Fatal(err)
	}

	wantPatch, err := GenerateBuffer(oldData, newData)
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}
	if err := os.WriteFile(patchPath, []byte("previous patch contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateFile(oldPath, newPath, patchPath); err != nil {
		t.Fatalf("GenerateFile: %v", err)
	}
	gotPatch, err := os.ReadFile(patchPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPatch, wantPatch) {
		t.Fatal("GenerateFile patch differs from GenerateBuffer patch")
	}
	temporaryPatches, err := filepath.Glob(filepath.Join(tempDir, ".update.patch.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaryPatches) != 0 {
		t.Fatalf("temporary patches remain after atomic install: %v", temporaryPatches)
	}

	if err := ApplyFile(oldPath, patchPath, appliedPath); err != nil {
		t.Fatalf("ApplyFile: %v", err)
	}
	applied, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(applied, newData) {
		t.Fatal("ApplyFile output differs from target")
	}

	expectedDigest := sha256.Sum256(newData)
	verifiedPath := filepath.Join(tempDir, "verified.bin")
	if err := ApplyFileWithOptions(oldPath, patchPath, verifiedPath, ApplyFileOptions{
		ExpectedNewSHA256: expectedDigest[:],
	}); err != nil {
		t.Fatalf("verified ApplyFile: %v", err)
	}

	protectedPath := filepath.Join(tempDir, "protected.bin")
	if err := os.WriteFile(protectedPath, []byte("existing output"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrongDigest := expectedDigest
	wrongDigest[0] ^= 0xFF
	if err := ApplyFileWithOptions(oldPath, patchPath, protectedPath, ApplyFileOptions{
		ExpectedNewSHA256: wrongDigest[:],
	}); err == nil {
		t.Fatal("ApplyFile accepted an incorrect trusted digest")
	}
	protectedData, err := os.ReadFile(protectedPath)
	if err != nil || string(protectedData) != "existing output" {
		t.Fatalf("failed apply changed existing output: %q, %v", protectedData, err)
	}
	temporaryOutputs, err := filepath.Glob(filepath.Join(tempDir, ".protected.bin.tmp-*"))
	if err != nil || len(temporaryOutputs) != 0 {
		t.Fatalf("temporary apply outputs remain: %v, %v", temporaryOutputs, err)
	}

	into := make([]byte, len(newData))
	if err := ApplyTo(oldData, gotPatch, into); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	if !bytes.Equal(into, newData) {
		t.Fatal("ApplyTo output differs from target")
	}
	if err := ApplyTo(oldData, gotPatch, into[:len(into)-1]); err == nil {
		t.Fatal("ApplyTo accepted an incorrectly sized output buffer")
	} else {
		var zucchiniErr *Error
		if !errors.As(err, &zucchiniErr) || zucchiniErr.Code != StatusInvalidNewImage {
			t.Fatalf("ApplyTo size error = %v, want StatusInvalidNewImage", err)
		}
	}

	wrongOldPath := filepath.Join(tempDir, "wrong-old.bin")
	rejectedPath := filepath.Join(tempDir, "rejected.bin")
	if err := os.WriteFile(wrongOldPath, []byte("not the expected old file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFile(wrongOldPath, patchPath, rejectedPath); err == nil {
		t.Fatal("ApplyFile accepted an incorrect old file")
	} else {
		var zucchiniErr *Error
		if !errors.As(err, &zucchiniErr) || zucchiniErr.Code != StatusInvalidOldImage {
			t.Fatalf("ApplyFile old image error = %v, want StatusInvalidOldImage", err)
		}
	}
	if _, err := os.Stat(rejectedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected output exists or cannot be inspected: %v", err)
	}
}

func TestApplyFileRejectsInvalidTrustedDigestLength(t *testing.T) {
	err := ApplyFileWithOptions("old", "patch", "new", ApplyFileOptions{ExpectedNewSHA256: []byte{1}})
	var zucchiniErr *Error
	if !errors.As(err, &zucchiniErr) || zucchiniErr.Code != StatusInvalidParam {
		t.Fatalf("ApplyFileWithOptions() error = %v, want StatusInvalidParam", err)
	}
}
