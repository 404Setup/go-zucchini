//go:build zucchini_asmcorpus

package zucchini

// Temporary Phase 0 instrumentation for ASM_PLAN.md. The plan requires a stable
// baseline over several representative PE/ELF pairs before any assembly kernel
// is judged, recording patch SHA-256, ns/op, B/op, peak heap, and build
// provenance. Throughput lives in BenchmarkGenerateCorpus; everything the timed
// loop cannot measure without perturbing itself lives in TestZZCorpusProbe.
//
// Populate the corpus with scripts/asm-corpus.ps1. Not part of the library.

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

const (
	corpusDirEnv     = "ZUCCHINI_BENCH_CORPUS"
	corpusIncludeEnv = "ZUCCHINI_BENCH_INCLUDE"
	corpusProbeEnv   = "ZUCCHINI_CORPUS_PROBE"
	defaultCorpusDir = ".asmbench/corpus"
	corpusOldName    = "old.bin"
	corpusNewName    = "new.bin"
)

type corpusPair struct {
	name    string
	oldPath string
	newPath string
}

// corpusPairs enumerates <corpus>/<name>/{old.bin,new.bin}. os.ReadDir sorts by
// filename, so baseline and candidate runs always visit pairs in the same order
// and their sample sequences stay comparable.
func corpusPairs(tb testing.TB) []corpusPair {
	tb.Helper()
	root := os.Getenv(corpusDirEnv)
	if root == "" {
		root = defaultCorpusDir
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		tb.Skipf("corpus unavailable at %s: %v (build it with scripts/asm-corpus.ps1)", root, err)
	}
	include := os.Getenv(corpusIncludeEnv)
	if include == "" {
		include = "."
	}
	filter, err := regexp.Compile(include)
	if err != nil {
		tb.Fatalf("invalid %s regular expression %q: %v", corpusIncludeEnv, include, err)
	}
	var pairs []corpusPair
	for _, entry := range entries {
		if !entry.IsDir() || !filter.MatchString(entry.Name()) {
			continue
		}
		pair := corpusPair{
			name:    entry.Name(),
			oldPath: filepath.Join(root, entry.Name(), corpusOldName),
			newPath: filepath.Join(root, entry.Name(), corpusNewName),
		}
		if isNonEmptyFile(pair.oldPath) && isNonEmptyFile(pair.newPath) {
			pairs = append(pairs, pair)
		}
	}
	if len(pairs) == 0 {
		tb.Skipf("no %s/%s pairs found under %s", corpusOldName, corpusNewName, root)
	}
	return pairs
}

func isNonEmptyFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// BenchmarkGenerateCorpus reports ns/op and B/op for every corpus pair. Peak
// heap is measured in TestZZCorpusProbe instead, because sampling MemStats from
// inside the timed loop would change the number it is trying to report.
func BenchmarkGenerateCorpus(b *testing.B) {
	for _, pair := range corpusPairs(b) {
		patchPath := filepath.Join(b.TempDir(), "corpus.patch")
		b.Run(pair.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := GenerateFile(pair.oldPath, pair.newPath, patchPath); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestZZCorpusProbe records one machine-readable CORPUS line per pair so a
// baseline run and a candidate run can be diffed directly. A patch that does
// not reconstruct the target byte-for-byte fails the pair.
func TestZZCorpusProbe(t *testing.T) {
	if os.Getenv(corpusProbeEnv) == "" {
		t.Skipf("set %s=1 to run the ASM_PLAN Phase 0 corpus probe", corpusProbeEnv)
	}
	t.Logf("BUILD version=%s goos=%s goarch=%s cpus=%d %s",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), recordedBuildSettings())

	for _, pair := range corpusPairs(t) {
		t.Run(pair.name, func(t *testing.T) {
			newSum, newSize := hashFile(t, pair.newPath)
			oldSum, oldSize := hashFile(t, pair.oldPath)

			workDir := t.TempDir()
			patchPath := filepath.Join(workDir, "corpus.patch")

			runtime.GC()
			var base runtime.MemStats
			runtime.ReadMemStats(&base)
			sampler := startPeakSampler()
			start := time.Now()
			err := GenerateFile(pair.oldPath, pair.newPath, patchPath)
			elapsed := time.Since(start)
			heap, sys, total := sampler.finish()
			if err != nil {
				t.Fatalf("GenerateFile: %v", err)
			}
			patchSum, patchSize := hashFile(t, patchPath)

			rebuiltPath := filepath.Join(workDir, "rebuilt.bin")
			if err := ApplyFile(pair.oldPath, patchPath, rebuiltPath); err != nil {
				t.Fatalf("ApplyFile: %v", err)
			}
			rebuiltSum, rebuiltSize := hashFile(t, rebuiltPath)
			if rebuiltSum != newSum || rebuiltSize != newSize {
				t.Fatalf("round trip mismatch: got %s (%d bytes), want %s (%d bytes)",
					rebuiltSum, rebuiltSize, newSum, newSize)
			}

			t.Logf("CORPUS name=%s old=%d new=%d patch=%d ratio=%.5f elapsedMs=%d "+
				"peakHeapMiB=%.1f peakSysMiB=%.1f allocMiB=%.1f patchSHA256=%s oldSHA256=%s newSHA256=%s",
				pair.name, oldSize, newSize, patchSize, float64(patchSize)/float64(newSize),
				elapsed.Milliseconds(), mib(heap), mib(sys), mib(total-base.TotalAlloc),
				patchSum, oldSum, newSum)
		})
	}
}

// recordedBuildSettings reports the build inputs Phase 0 must pin, notably
// GOAMD64, GOEXPERIMENT, and the active build tags.
func recordedBuildSettings() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "buildinfo=unavailable"
	}
	wanted := []string{"GOAMD64", "GOEXPERIMENT", "GOARM64", "CGO_ENABLED", "-tags", "-pgo", "-gcflags", "vcs.revision", "vcs.modified"}
	parts := make([]string, 0, len(wanted))
	for _, key := range wanted {
		for _, setting := range info.Settings {
			if setting.Key == key {
				parts = append(parts, key+"="+setting.Value)
				break
			}
		}
	}
	if len(parts) == 0 {
		return "buildinfo=empty"
	}
	return strings.Join(parts, " ")
}

// hashFile streams the file so hashing a 28 MiB input does not disturb the
// heap measurement taken around generation.
func hashFile(tb testing.TB, path string) (string, int64) {
	tb.Helper()
	file, err := os.Open(path)
	if err != nil {
		tb.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		tb.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), size
}
