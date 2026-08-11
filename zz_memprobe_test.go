//go:build zucchini_memprobe

package zucchini

// Temporary instrumentation used to measure peak memory and verify that
// optimizations keep patch output byte-identical. Not part of the library.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const (
	memprobeOldEnv = "ZUCCHINI_MEMPROBE_OLD"
	memprobeNewEnv = "ZUCCHINI_MEMPROBE_NEW"
)

func memprobeInputs(t *testing.T) (oldPath, newPath string, oldImage, newImage []byte) {
	t.Helper()
	oldPath = os.Getenv(memprobeOldEnv)
	newPath = os.Getenv(memprobeNewEnv)
	if oldPath == "" || newPath == "" {
		t.Skipf("set %s and %s to run memory probes", memprobeOldEnv, memprobeNewEnv)
	}
	var err error
	oldImage, err = os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read old input: %v", err)
	}
	newImage, err = os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read new input: %v", err)
	}
	return oldPath, newPath, oldImage, newImage
}

// TestZZApplyMemProbe isolates patch application from generation. The patch is
// created outside this test so GenerateBuffer's temporary heap cannot affect
// the Apply measurement.
func TestZZApplyMemProbe(t *testing.T) {
	_, _, oldImage, expected := memprobeInputs(t)
	patchBytes, err := GenerateBuffer(oldImage, expected)
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	newImage, err := Apply(oldImage, patchBytes)
	elapsed := time.Since(start)
	heap, sys, total := p.finish()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !bytes.Equal(newImage, expected) {
		t.Fatal("applied image differs from the configured new input")
	}

	sum := sha256.Sum256(newImage)
	t.Logf("INPUTS      old=%.1f MiB patch=%.1f MiB", mib(uint64(len(oldImage))), mib(uint64(len(patchBytes))))
	t.Logf("OUTPUT      %.1f MiB sha256=%s", mib(uint64(len(newImage))), hex.EncodeToString(sum[:]))
	t.Logf("BASE HEAP   %.1f MiB", mib(base.HeapAlloc))
	t.Logf("PEAK HEAP   %.1f MiB (delta %.1f MiB)", mib(heap), mib(heap-base.HeapAlloc))
	t.Logf("PEAK SYS    %.1f MiB", mib(sys))
	t.Logf("TOTAL ALLOC %.1f MiB (during Apply)", mib(total-base.TotalAlloc))
	t.Logf("ELAPSED     %s", elapsed)
}

func TestZZGenerateFileMemProbe(t *testing.T) {
	oldPath, newPath, _, _ := memprobeInputs(t)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	patchPath := filepath.Join(t.TempDir(), "apply_probe.patch")
	err := GenerateFile(oldPath, newPath, patchPath)
	elapsed := time.Since(start)
	heap, sys, total := p.finish()
	if err != nil {
		t.Fatalf("GenerateFile: %v", err)
	}
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(patchBytes)
	t.Logf("PATCH       %d bytes sha256=%s", len(patchBytes), hex.EncodeToString(sum[:]))
	t.Logf("BASE HEAP   %.1f MiB", mib(base.HeapAlloc))
	t.Logf("PEAK HEAP   %.1f MiB (delta %.1f MiB)", mib(heap), mib(heap-base.HeapAlloc))
	t.Logf("PEAK SYS    %.1f MiB", mib(sys))
	t.Logf("TOTAL ALLOC %.1f MiB (during GenerateFile)", mib(total-base.TotalAlloc))
	t.Logf("ELAPSED     %s", elapsed)
}

func TestZZApplyFileMemProbe(t *testing.T) {
	oldPath, _, oldImage, expected := memprobeInputs(t)
	workDir := t.TempDir()
	patchPath := filepath.Join(workDir, "apply-probe.patch")
	patchBytes, err := GenerateBuffer(oldImage, expected)
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}
	if err := os.WriteFile(patchPath, patchBytes, 0o644); err != nil {
		t.Fatalf("write patch: %v", err)
	}
	outputPath := filepath.Join(workDir, "apply-probe-output.bin")

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	err = ApplyFile(oldPath, patchPath, outputPath)
	elapsed := time.Since(start)
	heap, sys, total := p.finish()
	if err != nil {
		t.Fatalf("ApplyFile: %v", err)
	}
	newImage, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newImage, expected) {
		t.Fatal("ApplyFile output differs from the configured new input")
	}
	sum := sha256.Sum256(newImage)
	t.Logf("OUTPUT      %.1f MiB sha256=%s", mib(uint64(len(newImage))), hex.EncodeToString(sum[:]))
	t.Logf("BASE HEAP   %.1f MiB", mib(base.HeapAlloc))
	t.Logf("PEAK HEAP   %.1f MiB (delta %.1f MiB)", mib(heap), mib(heap-base.HeapAlloc))
	t.Logf("PEAK SYS    %.1f MiB", mib(sys))
	t.Logf("TOTAL ALLOC %.1f MiB (during ApplyFile)", mib(total-base.TotalAlloc))
	t.Logf("ELAPSED     %s", elapsed)
}

// TestZZMemProbe reports peak memory for a configured generation pair and
// prints the patch hash, which must stay constant across optimizations.
func TestZZMemProbe(t *testing.T) {
	_, _, oldImage, newImage := memprobeInputs(t)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	patchBytes, err := GenerateBuffer(oldImage, newImage)
	elapsed := time.Since(start)
	heap, sys, total := p.finish()
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}

	sum := sha256.Sum256(patchBytes)
	t.Logf("IMAGES      old=%.1f MiB new=%.1f MiB", mib(uint64(len(oldImage))), mib(uint64(len(newImage))))
	t.Logf("PATCH       %d bytes  sha256=%s", len(patchBytes), hex.EncodeToString(sum[:]))
	t.Logf("PEAK HEAP   %.1f MiB", mib(heap))
	t.Logf("PEAK SYS    %.1f MiB", mib(sys))
	t.Logf("TOTAL ALLOC %.1f MiB (cumulative)", mib(total))
	t.Logf("ELAPSED     %s", elapsed)
}
