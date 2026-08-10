package sais

import (
	"bytes"
	"slices"
	"sort"
	"testing"
)

func naiveSuffixSort(str []byte) []uint32 {
	n := len(str)
	sa := make([]uint32, n)
	for i := range n {
		sa[i] = uint32(i)
	}
	sort.Slice(sa, func(i, j int) bool {
		return bytes.Compare(str[sa[i]:], str[sa[j]:]) < 0
	})
	return sa
}

func TestSAIS(t *testing.T) {
	testCases := [][]byte{
		[]byte("banana"),
		[]byte("mississippi"),
		[]byte("abracadabra"),
		[]byte("aaaaaaaaa"),
		[]byte("abcdefghijklmnopqrstuvwxyz"),
		[]byte("zyxwvutsrqponmlkjihgfedcba"),
		[]byte("the quick brown fox jumps over the lazy dog"),
	}

	for _, tc := range testCases {
		expected := naiveSuffixSort(tc)
		actual := MakeSuffixArray(tc, 256)

		if len(expected) != len(actual) {
			t.Fatalf("Length mismatch for %s: expected %d, got %d", string(tc), len(expected), len(actual))
		}

		for i := range expected {
			if expected[i] != actual[i] {
				t.Fatalf("Mismatch for %s at index %d: expected %d, got %d\nExpected SA: %v\nActual SA: %v",
					string(tc), i, expected[i], actual[i], expected, actual)
			}
		}
	}
}

func TestSuffixLowerBound(t *testing.T) {
	str := []byte("banana")
	sa := MakeSuffixArray(str, 256)

	idx := SuffixLowerBound(sa, str, []byte("an"))
	if idx < len(sa) {
		matchedSuffix := string(str[sa[idx]:])
		if matchedSuffix != "ana" {
			t.Fatalf("Expected lower bound for 'an' to point to 'ana', got '%s'", matchedSuffix)
		}
	} else {
		t.Fatal("SuffixLowerBound returned out of range index")
	}
}

func TestProjectionSourceSuffixArray(t *testing.T) {
	image := []byte{7, 3, 9, 1, 3, 7, 2, 9}
	refStart := []uint64{1 << 2}
	refCover := []uint64{(1 << 2) | (1 << 3)}
	refRank := []uint32{0, 1}
	refProj := []uint32{300}
	source := NewProjectionSource(image, refStart, refCover, refRank, refProj)
	projected := []uint32{7, 3, 300, 256, 3, 7, 2, 9}

	want := naiveSuffixSortU32(projected)
	got := MakeSuffixArraySourceInto(source, 301, nil)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SA[%d]=%d, want %d", i, got[i], want[i])
		}
	}
}

func TestWorkspaceReusesBackingStorage(t *testing.T) {
	input := uint32Slice{3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9}
	var workspace Workspace
	sa := MakeSuffixArraySourceIntoWithWorkspace(input, 10, nil, &workspace)
	if len(workspace.levels) == 0 || len(workspace.levels[0].sl) == 0 || len(workspace.levels[0].scratch) == 0 {
		t.Fatal("workspace was not populated")
	}
	firstSL := &workspace.levels[0].sl[0]
	firstScratch := &workspace.levels[0].scratch[0]
	want := slices.Clone(sa)

	sa = MakeSuffixArraySourceIntoWithWorkspace(input, 10, sa, &workspace)
	if firstSL != &workspace.levels[0].sl[0] || firstScratch != &workspace.levels[0].scratch[0] {
		t.Fatal("workspace backing storage was replaced for an equal-sized input")
	}
	if !slices.Equal(sa, want) {
		t.Fatalf("reused suffix array differs: got %v, want %v", sa, want)
	}
}
