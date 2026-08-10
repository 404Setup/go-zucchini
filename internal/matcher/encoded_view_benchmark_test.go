package matcher

import "testing"

func BenchmarkEncodedViewQueryAt(b *testing.B) {
	const size = 64 << 10
	image := make([]byte, size)
	for i := range image {
		image[i] = byte(i*37 + 11)
	}
	raw := NewEncodedView(NewImageIndex(image))
	mixedIndex := NewImageIndex(image)
	mixedIndex.refStart = make([]uint64, size/64)
	mixedIndex.refCover = make([]uint64, len(mixedIndex.refStart))
	refProj := make([]uint32, 0, size/32)
	for start := 0; start < size; start += 32 {
		mixedIndex.markRefStart(start)
		for i := start; i < start+4; i++ {
			mixedIndex.markRefCovered(i)
		}
		refProj = append(refProj, uint32(300+len(refProj)))
	}
	mixedIndex.buildRefRank()
	mixed := NewEncodedView(mixedIndex)
	mixed.refProj = refProj

	for _, benchmark := range []struct {
		name string
		view *EncodedView
	}{
		{name: "raw", view: raw},
		{name: "mixed", view: mixed},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			var sum uint32
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				sum += benchmark.view.QueryAt(i & (size - 1))
			}
			encodedQuerySink = sum
		})
	}
}

var encodedQuerySink uint32
