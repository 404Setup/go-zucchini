package zucchini

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkGenerateFile is the representative workload used to collect PGO
// profiles. Override the inputs when profiling production data.
func BenchmarkGenerateFile(b *testing.B) {
	oldPath := os.Getenv("ZUCCHINI_BENCH_OLD")
	newPath := os.Getenv("ZUCCHINI_BENCH_NEW")
	if oldPath == "" || newPath == "" {
		b.Skip("set ZUCCHINI_BENCH_OLD and ZUCCHINI_BENCH_NEW to benchmark file inputs")
	}
	if _, err := os.Stat(oldPath); err != nil {
		b.Skipf("old benchmark input unavailable: %v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		b.Skipf("new benchmark input unavailable: %v", err)
	}

	patchPath := filepath.Join(b.TempDir(), "benchmark.patch")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := GenerateFile(oldPath, newPath, patchPath); err != nil {
			b.Fatal(err)
		}
	}
}
