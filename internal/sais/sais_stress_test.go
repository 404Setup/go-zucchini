package sais

import (
	"math/bits"
	"math/rand"
	"slices"
	"sort"
	"testing"
)

// naiveSuffixSortU32 sorts suffixes of str lexicographically, by index.
func naiveSuffixSortU32(str []uint32) []uint32 {
	n := len(str)
	sa := make([]uint32, n)
	for i := range sa {
		sa[i] = uint32(i)
	}
	sort.SliceStable(sa, func(a, b int) bool {
		x, y := str[sa[a]:], str[sa[b]:]
		m := min(len(y), len(x))
		for k := 0; k < m; k++ {
			if x[k] != y[k] {
				return x[k] < y[k]
			}
		}
		return len(x) < len(y)
	})
	return sa
}

// TestSAISRandomized compares MakeSuffixArrayInt against a naive reference over
// many randomized inputs, spanning alphabet sizes and lengths. Small alphabets
// force deep SA-IS recursion, which is where index-width bugs surface.
func TestSAISRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(20260806))
	for _, keyBound := range []int{2, 3, 5, 17, 256, 260} {
		for _, n := range []int{1, 2, 3, 7, 8, 15, 31, 64, 100, 257, 1000, 4096} {
			for trial := range 8 {
				str := make([]uint32, n)
				for i := range str {
					str[i] = uint32(rng.Intn(keyBound))
				}
				want := naiveSuffixSortU32(str)
				got := MakeSuffixArrayInt(str, keyBound)
				if len(got) != len(want) {
					t.Fatalf("keyBound=%d n=%d: length %d, want %d", keyBound, n, len(got), len(want))
				}
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("keyBound=%d n=%d trial=%d: SA[%d]=%d, want %d\nstr=%v\ngot =%v\nwant=%v",
							keyBound, n, trial, i, got[i], want[i], str, got, want)
					}
				}
			}
		}
	}
}

// TestSAISExhaustiveSmall exercises every string through length 8 for small
// alphabets. This catches relocation cycles and equal-LMS labeling cases that
// are easy for randomized coverage to miss.
func TestSAISExhaustiveSmall(t *testing.T) {
	for alphabet := 1; alphabet <= 4; alphabet++ {
		for length := 0; length <= 8; length++ {
			count := 1
			for range length {
				count *= alphabet
			}
			for encoded := 0; encoded < count; encoded++ {
				value := encoded
				input := make([]uint32, length)
				for i := range input {
					input[i] = uint32(value % alphabet)
					value /= alphabet
				}
				want := naiveSuffixSortU32(input)
				got := MakeSuffixArrayInt(input, alphabet)
				if !slices.Equal(got, want) {
					t.Fatalf("alphabet=%d length=%d encoded=%d: got %v, want %v; input=%v",
						alphabet, length, encoded, got, want, input)
				}
			}
		}
	}
}

func TestSAISMaximumLMSDensity(t *testing.T) {
	for _, length := range []int{2, 3, 31, 32, 63, 64, 65, 255, 256, 257, 4095, 4096, 4097} {
		input := make([]uint32, length)
		for i := range input {
			if i&1 == 0 {
				input[i] = 3
			} else {
				input[i] = uint32((i / 2) & 1)
			}
		}
		want := naiveSuffixSortU32(input)
		got := MakeSuffixArrayInt(input, 4)
		if !slices.Equal(got, want) {
			t.Fatalf("length=%d: suffix array differs at maximum LMS density", length)
		}
	}
}

func TestSAISLMSCountBoundaries(t *testing.T) {
	// For an even-length [1,0,1,0,...] input, every odd position is LMS.
	// Suffixes sort by symbol and then from shortest to longest, giving a
	// linear oracle even at the uint8/uint16 LMS-count boundaries.
	for _, length := range []int{510, 512, 131070, 131072} {
		input := make([]uint32, length)
		for i := range input {
			input[i] = uint32((i + 1) & 1)
		}
		got := MakeSuffixArrayInt(input, 2)
		rank := 0
		for suffix := length - 1; suffix >= 1; suffix -= 2 {
			if got[rank] != uint32(suffix) {
				t.Fatalf("length=%d: SA[%d]=%d, want %d", length, rank, got[rank], suffix)
			}
			rank++
		}
		for suffix := length - 2; suffix >= 0; suffix -= 2 {
			if got[rank] != uint32(suffix) {
				t.Fatalf("length=%d: SA[%d]=%d, want %d", length, rank, got[rank], suffix)
			}
			rank++
		}
	}
}

func FuzzSAISBytes(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {1, 0, 1, 0}, []byte("mississippi")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			t.Skip()
		}
		want := naiveSuffixSort(input)
		got := MakeSuffixArray(input, 256)
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v; input=%v", got, want, input)
		}
	})
}

func FuzzSAISUint32(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {0, 1, 2, 3}, {255, 0, 255, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			t.Skip()
		}
		input := make([]uint32, len(data))
		for i, value := range data {
			switch i % 5 {
			case 0:
				input[i] = uint32(value)
			case 1:
				input[i] = 256 + uint32(value&1)
			case 2:
				input[i] = 65535 + uint32(value&1)
			default:
				input[i] = uint32(value & 3)
			}
		}
		want := naiveSuffixSortU32(input)
		got := MakeSuffixArrayInt(input, 65537)
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v; input=%v", got, want, input)
		}
	})
}

func FuzzSAISProjectionSource(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {13, 1, 26, 2}, {63, 64, 127, 128}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, image []byte) {
		if len(image) > 512 {
			t.Skip()
		}
		refStart := make([]uint64, (len(image)+63)/64)
		refCover := make([]uint64, len(refStart))
		refRank := make([]uint32, len(refStart)+1)
		refProj := make([]uint32, 0, len(image)/13+1)
		projected := make([]uint32, len(image))
		for i, value := range image {
			projected[i] = uint32(value)
			if value%13 == 0 {
				refStart[i>>6] |= 1 << uint(i&63)
				refCover[i>>6] |= 1 << uint(i&63)
				projection := 300 + uint32(value&3)
				refProj = append(refProj, projection)
				projected[i] = projection
			}
		}
		var rank uint32
		for word, starts := range refStart {
			refRank[word] = rank
			rank += uint32(bits.OnesCount64(starts))
		}
		if len(refRank) > 0 {
			refRank[len(refStart)] = rank
		}
		source := NewProjectionSource(image, refStart, refCover, refRank, refProj)
		want := naiveSuffixSortU32(projected)
		got := MakeSuffixArraySourceInto(source, 304, nil)
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v; projection=%v", got, want, projected)
		}
	})
}

// TestSAISRepeated covers highly repetitive inputs, which stress the LMS
// labeling and recursion paths differently from random data.
func TestSAISRepeated(t *testing.T) {
	inputs := [][]uint32{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{1, 1, 1, 1, 1, 1, 1, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
		{2, 1, 0, 2, 1, 0, 2, 1, 0},
		{1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1},
	}
	for _, str := range inputs {
		maxV := uint32(0)
		for _, v := range str {
			if v > maxV {
				maxV = v
			}
		}
		want := naiveSuffixSortU32(str)
		got := MakeSuffixArrayInt(str, int(maxV)+1)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("str=%v: SA[%d]=%d, want %d\ngot =%v\nwant=%v", str, i, got[i], want[i], got, want)
			}
		}
	}
}

// TestSAISStructuredData exercises the byte-alphabet path with repeated pages,
// long common prefixes, and deterministic local mutations.
func TestSAISStructuredData(t *testing.T) {
	data := make([]byte, 16*1024)
	for i := range data {
		data[i] = byte((i*31 + i/97) & 0xFF)
		if i%1024 < 192 {
			data[i] = byte(i % 17)
		}
	}
	str := make([]uint32, len(data))
	for i, b := range data {
		str[i] = uint32(b)
	}
	want := naiveSuffixSortU32(str)
	got := MakeSuffixArray(data, 256)
	if len(got) != len(want) {
		t.Fatalf("length %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SA[%d]=%d, want %d (suffixes differ at rank %d)", i, got[i], want[i], i)
		}
	}
}

// TestMakeSuffixArrayIntIntoReuse verifies the buffer-reusing variant produces
// identical output to the allocating one, including when the buffer is reused
// across differently-sized inputs.
func TestMakeSuffixArrayIntIntoReuse(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var buf []uint32
	for _, n := range []int{500, 100, 500, 1000, 250} {
		str := make([]uint32, n)
		for i := range str {
			str[i] = uint32(rng.Intn(16))
		}
		want := MakeSuffixArrayInt(str, 16)
		if len(buf) != n {
			buf = make([]uint32, n)
		}
		got := MakeSuffixArrayIntInto(str, 16, buf)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("n=%d: SA[%d]=%d, want %d", n, i, got[i], want[i])
			}
		}
	}
}
