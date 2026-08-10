package sais

import (
	"math/bits"
	"testing"
)

func projectionSourceFixture(size int) (*ProjectionSource, []uint32) {
	image := make([]byte, size)
	refStart := make([]uint64, (size+63)/64)
	refCover := make([]uint64, len(refStart))
	refRank := make([]uint32, len(refStart)+1)
	want := make([]uint32, size)
	for i := range image {
		image[i] = byte(i*37 + 11)
		want[i] = uint32(image[i])
	}

	starts := []int{0, 31, 63, 64, 95, 127, 128, 191, 255}
	refProj := make([]uint32, 0, len(starts))
	for _, start := range starts {
		if start >= size {
			continue
		}
		refStart[start>>6] |= 1 << uint(start&63)
		projection := uint32(300 + len(refProj))
		refProj = append(refProj, projection)
		want[start] = projection
		for i := start + 1; i < min(start+4, size); i++ {
			refCover[i>>6] |= 1 << uint(i&63)
			want[i] = 256
		}
		refCover[start>>6] |= 1 << uint(start&63)
	}
	var rank uint32
	for word, starts := range refStart {
		refRank[word] = rank
		rank += uint32(bits.OnesCount64(starts))
	}
	refRank[len(refStart)] = rank
	return NewProjectionSource(image, refStart, refCover, refRank, refProj), want
}

func TestProjectionSourceQueryAtBoundaries(t *testing.T) {
	source, want := projectionSourceFixture(320)
	for i, expected := range want {
		if got := source.QueryAt(i); got != expected {
			t.Fatalf("QueryAt(%d)=%d, want %d", i, got, expected)
		}
		got, ordinary := source.queryOrdinary(i)
		if !ordinary {
			got = source.referenceProjectionCold(i)
		}
		if got != expected {
			t.Fatalf("specialized query at %d=%d, want %d", i, got, expected)
		}
	}
}

func TestProjectionSourceSuffixArrayBoundaries(t *testing.T) {
	source, projected := projectionSourceFixture(320)
	want := naiveSuffixSortU32(projected)
	got := MakeSuffixArraySourceInto(source, 309, nil)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SA[%d]=%d, want %d", i, got[i], want[i])
		}
	}
}

func denseProjectionSource(size int) (*ProjectionSource, int) {
	image := make([]byte, size)
	refStart := make([]uint64, (size+63)/64)
	refCover := make([]uint64, len(refStart))
	refRank := make([]uint32, len(refStart)+1)
	refProj := make([]uint32, 0, size/32)
	for i := range image {
		image[i] = byte(i*37 + 11)
	}
	for start := 0; start < size; start += 32 {
		refStart[start>>6] |= 1 << uint(start&63)
		for i := start; i < start+4; i++ {
			refCover[i>>6] |= 1 << uint(i&63)
		}
		refProj = append(refProj, uint32(300+len(refProj)))
	}
	var rank uint32
	for word, starts := range refStart {
		refRank[word] = rank
		rank += uint32(bits.OnesCount64(starts))
	}
	refRank[len(refStart)] = rank
	return NewProjectionSource(image, refStart, refCover, refRank, refProj), 300 + len(refProj)
}

func BenchmarkProjectionSourceQueryAt(b *testing.B) {
	const size = 64 << 10
	mixed, _ := denseProjectionSource(size)
	image := mixed.image
	raw := NewProjectionSource(image, nil, nil, nil, nil)

	for _, benchmark := range []struct {
		name   string
		source *ProjectionSource
	}{
		{name: "raw", source: raw},
		{name: "mixed", source: mixed},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			var sum uint32
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				sum += benchmark.source.QueryAt(i & (size - 1))
			}
			projectionQuerySink = sum
		})
	}
}

func BenchmarkProjectionSuffixArray(b *testing.B) {
	const size = 64 << 10
	source, keyBound := denseProjectionSource(size)
	sa := make([]uint32, size)
	var workspace Workspace

	b.ReportAllocs()
	b.SetBytes(size)
	b.ResetTimer()
	for range b.N {
		sa = MakeSuffixArraySourceIntoWithWorkspace(source, keyBound, sa, &workspace)
	}
	projectionSASink = sa[0]
}

var projectionQuerySink uint32
var projectionSASink uint32
