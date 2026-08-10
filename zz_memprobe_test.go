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

// TestZZApplyMemProbe isolates patch application from generation. The patch is
// created outside this test so GenerateBuffer's temporary heap cannot affect
// the Apply measurement.
func TestZZApplyMemProbe(t *testing.T) {
	oldImage, err := os.ReadFile("v1.exe")
	if err != nil {
		t.Skipf("v1.exe not available: %v", err)
	}
	patchBytes, err := os.ReadFile("apply_probe.patch")
	if err != nil {
		t.Skipf("apply_probe.patch not available: %v", err)
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

	expected, err := os.ReadFile("v2.exe")
	if err != nil {
		t.Fatalf("read v2.exe: %v", err)
	}
	if !bytes.Equal(newImage, expected) {
		t.Fatal("applied image differs from v2.exe")
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
	if os.Getenv("ZUCCHINI_FILE_MEMPROBE") == "" {
		t.Skip("set ZUCCHINI_FILE_MEMPROBE=1 to run file-backed memory probes")
	}

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	patchPath := filepath.Join(t.TempDir(), "apply_probe.patch")
	err := GenerateFile("v1.exe", "v2.exe", patchPath)
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
	if os.Getenv("ZUCCHINI_FILE_MEMPROBE") == "" {
		t.Skip("set ZUCCHINI_FILE_MEMPROBE=1 to run file-backed memory probes")
	}
	if _, err := os.Stat("apply_probe.patch"); err != nil {
		t.Skipf("apply_probe.patch not available: %v", err)
	}
	const outputPath = "apply_probe_output.exe"
	defer os.Remove(outputPath)

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	p := startPeakSampler()
	start := time.Now()
	err := ApplyFile("v1.exe", "apply_probe.patch", outputPath)
	elapsed := time.Since(start)
	heap, sys, total := p.finish()
	if err != nil {
		t.Fatalf("ApplyFile: %v", err)
	}
	newImage, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("v2.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newImage, expected) {
		t.Fatal("ApplyFile output differs from v2.exe")
	}
	sum := sha256.Sum256(newImage)
	t.Logf("OUTPUT      %.1f MiB sha256=%s", mib(uint64(len(newImage))), hex.EncodeToString(sum[:]))
	t.Logf("BASE HEAP   %.1f MiB", mib(base.HeapAlloc))
	t.Logf("PEAK HEAP   %.1f MiB (delta %.1f MiB)", mib(heap), mib(heap-base.HeapAlloc))
	t.Logf("PEAK SYS    %.1f MiB", mib(sys))
	t.Logf("TOTAL ALLOC %.1f MiB (during ApplyFile)", mib(total-base.TotalAlloc))
	t.Logf("ELAPSED     %s", elapsed)
}

// TestZZMemProbe reports peak memory for a full v1.exe -> v2.exe generation and
// prints the patch hash, which must stay constant across optimizations.
func TestZZMemProbe(t *testing.T) {
	oldImage, err := os.ReadFile("v1.exe")
	if err != nil {
		t.Skipf("v1.exe not available: %v", err)
	}
	newImage, err := os.ReadFile("v2.exe")
	if err != nil {
		t.Skipf("v2.exe not available: %v", err)
	}

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
