//go:build amd64 && gc && !purego && asmcompare

package matcher

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

type encodedTestReference struct {
	start      int
	width      int
	projection uint32
}

func makeEncodedTestView(image []byte, refs []encodedTestReference) *EncodedView {
	idx := NewImageIndex(image)
	if len(refs) == 0 {
		return NewEncodedView(idx)
	}
	idx.refStart = make([]uint64, (len(image)+63)/64)
	idx.refCover = make([]uint64, len(idx.refStart))
	projections := make([]uint32, len(refs))
	for i, ref := range refs {
		idx.markRefStart(ref.start)
		for j := 0; j < ref.width; j++ {
			idx.markRefCovered(ref.start + j)
		}
		projections[i] = ref.projection
	}
	idx.buildRefRank()
	view := NewEncodedView(idx)
	view.refProj = projections
	return view
}

func compareEncodedPrefixScalar(oldView, newView *EncodedView, oldLo, newLo, limit int) int {
	for i := 0; i < limit; i++ {
		oldValue := oldView.QueryAt(oldLo + i)
		newValue := newView.QueryAt(newLo + i)
		if oldValue < newValue {
			return -1
		}
		if oldValue > newValue {
			return 1
		}
	}
	return 0
}

func comparisonSign(value int) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}

func TestCompareEncodedPrefixReferenceBoundaries(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	oldImage := make([]byte, 160)
	newImage := make([]byte, 160)
	if _, err := rng.Read(oldImage); err != nil {
		t.Fatal(err)
	}
	copy(newImage, oldImage)
	newImage[30] ^= 0x80
	newImage[129] ^= 0x40

	oldView := makeEncodedTestView(oldImage, []encodedTestReference{
		{start: 0, width: 4, projection: 300},
		{start: 31, width: 2, projection: 301},
		{start: 63, width: 4, projection: 302},
		{start: 95, width: 1, projection: 303},
		{start: 127, width: 4, projection: 304},
	})
	newView := makeEncodedTestView(newImage, []encodedTestReference{
		{start: 1, width: 4, projection: 300},
		{start: 32, width: 2, projection: 305},
		{start: 64, width: 4, projection: 302},
		{start: 96, width: 1, projection: 303},
		{start: 128, width: 4, projection: 304},
	})

	for oldLo := 0; oldLo < len(oldImage); oldLo++ {
		for newLo := 0; newLo < len(newImage); newLo++ {
			limit := min(len(oldImage)-oldLo, len(newImage)-newLo)
			for _, length := range []int{0, min(1, limit), min(31, limit), min(32, limit), min(33, limit), limit} {
				got := comparisonSign(compareEncodedPrefix(oldView, newView, oldLo, newLo, length))
				want := compareEncodedPrefixScalar(oldView, newView, oldLo, newLo, length)
				if got != want {
					t.Fatalf("oldLo=%d newLo=%d len=%d: got %d, want %d", oldLo, newLo, length, got, want)
				}
			}
		}
	}
}

func TestSuffixLowerBoundEncodedMatchesProjectionSort(t *testing.T) {
	oldView := makeEncodedTestView(
		[]byte("the quick brown fox jumps over the lazy dog"),
		[]encodedTestReference{{start: 4, width: 5, projection: 300}, {start: 31, width: 4, projection: 301}},
	)
	newView := makeEncodedTestView(
		[]byte("quick brown foxes jump over a lazy dog"),
		[]encodedTestReference{{start: 0, width: 5, projection: 300}, {start: 30, width: 4, projection: 301}},
	)
	sa := make([]uint32, oldView.Size())
	for i := range sa {
		sa[i] = uint32(i)
	}
	projected := func(view *EncodedView, start int) []uint32 {
		values := make([]uint32, view.Size()-start)
		for i := range values {
			values[i] = view.QueryAt(start + i)
		}
		return values
	}
	oldProjection := projected(oldView, 0)
	newProjection := projected(newView, 0)
	sort.Slice(sa, func(i, j int) bool {
		left := oldProjection[sa[i]:]
		right := oldProjection[sa[j]:]
		limit := min(len(left), len(right))
		for k := 0; k < limit; k++ {
			if left[k] != right[k] {
				return left[k] < right[k]
			}
		}
		return len(left) < len(right)
	})
	for queryLo := 0; queryLo < newView.Size(); queryLo++ {
		got := suffixLowerBoundEncoded(sa, oldView, newView, queryLo)
		want := saisLowerBoundForTest(sa, oldProjection, newProjection[queryLo:])
		if got != want {
			t.Fatalf("queryLo=%d: got %d, want %d", queryLo, got, want)
		}
	}
}

func saisLowerBoundForTest(sa []uint32, oldProjection, query []uint32) int {
	low, high := 0, len(sa)
	for low < high {
		mid := int(uint(low+high) >> 1)
		oldLo := int(sa[mid])
		limit := min(len(oldProjection)-oldLo, len(query))
		comparison := 0
		for i := 0; i < limit; i++ {
			if oldProjection[oldLo+i] < query[i] {
				comparison = -1
				break
			}
			if oldProjection[oldLo+i] > query[i] {
				comparison = 1
				break
			}
		}
		if comparison == 0 {
			comparison = comparisonSign(len(oldProjection) - oldLo - len(query))
		}
		if comparison >= 0 {
			high = mid
		} else {
			low = mid + 1
		}
	}
	return low
}

func FuzzCompareEncodedPrefix(f *testing.F) {
	f.Add(
		[]byte("ordinary reference boundary"),
		[]byte("ordinary reference mismatch"),
		[]byte{1, 0, 1, 0, 1},
		[]byte{0, 1, 0, 1, 0},
		uint16(3),
		uint16(4),
		uint16(17),
	)
	f.Fuzz(func(t *testing.T, oldImage, newImage, oldMarkers, newMarkers []byte, oldSeed, newSeed, lengthSeed uint16) {
		oldImage = oldImage[:min(len(oldImage), 512)]
		newImage = newImage[:min(len(newImage), 512)]
		makeRefs := func(image, markers []byte) []encodedTestReference {
			refs := make([]encodedTestReference, 0, min(len(image), len(markers))/8)
			for i := 0; i < min(len(image), len(markers)); i++ {
				if markers[i]&7 == 0 {
					refs = append(refs, encodedTestReference{start: i, width: 1, projection: 257 + uint32(markers[i])})
				}
			}
			return refs
		}
		oldView := makeEncodedTestView(oldImage, makeRefs(oldImage, oldMarkers))
		newView := makeEncodedTestView(newImage, makeRefs(newImage, newMarkers))
		if len(oldImage) == 0 || len(newImage) == 0 {
			return
		}
		oldLo := int(oldSeed) % len(oldImage)
		newLo := int(newSeed) % len(newImage)
		limit := int(lengthSeed) % (min(len(oldImage)-oldLo, len(newImage)-newLo) + 1)
		got := comparisonSign(compareEncodedPrefix(oldView, newView, oldLo, newLo, limit))
		want := compareEncodedPrefixScalar(oldView, newView, oldLo, newLo, limit)
		if got != want {
			t.Fatalf("oldLo=%d newLo=%d len=%d: got %d, want %d", oldLo, newLo, limit, got, want)
		}
	})
}

func BenchmarkCompareEncodedPrefixOrdinary(b *testing.B) {
	for _, size := range []int{256, 4096, 64 << 10} {
		oldImage := make([]byte, size)
		newImage := make([]byte, size)
		for i := range oldImage {
			oldImage[i] = byte(i*37 + 11)
			newImage[i] = oldImage[i]
		}
		oldView := makeEncodedTestView(oldImage, nil)
		newView := makeEncodedTestView(newImage, nil)

		b.Run(fmt.Sprintf("equal_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for range b.N {
				if got := compareEncodedPrefix(oldView, newView, 0, 0, size); got != 0 {
					b.Fatal(got)
				}
			}
		})

		newImage[size-1] ^= 1
		b.Run(fmt.Sprintf("mismatch_end_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for range b.N {
				if got := compareEncodedPrefix(oldView, newView, 0, 0, size); got >= 0 {
					b.Fatal(got)
				}
			}
		})
	}
}
