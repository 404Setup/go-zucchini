package matcher

import (
	"slices"
	"testing"

	"github.com/404Setup/go-zucchini/internal/sais"
	"github.com/404Setup/go-zucchini/internal/types"
)

func TestEncodedBuildMatchesGenericBuild(t *testing.T) {
	oldView := NewEncodedView(NewImageIndex([]byte("the quick brown fox jumps")))
	newView := NewEncodedView(NewImageIndex([]byte("the quick red fox jumps")))
	oldView.BuildProjectionCache()
	newView.BuildProjectionCache()
	oldSA := sais.MakeSuffixArraySourceInto(oldView.SuffixSource(), oldView.Cardinality(), nil)

	generic := NewEquivalenceMap()
	generic.BuildWithSource(oldSA, oldView, oldView, newView, nil, MinEquivalenceSimilarity)
	encoded := NewEquivalenceMap()
	encoded.BuildWithEncodedViews(oldSA, oldView, newView, nil, MinEquivalenceSimilarity)
	if !slices.Equal(generic.Candidates(), encoded.Candidates()) {
		t.Fatalf("encoded candidates differ: got %v, want %v", encoded.Candidates(), generic.Candidates())
	}
}

func TestBinaryDataHistogramAndOutlier(t *testing.T) {
	data1 := []byte("hello world zucchini differential patch engine test data 1234567890")
	data2 := []byte("hello world zucchini differential patch engine test data 1234567899")

	h1 := NewBinaryDataHistogram()
	h2 := NewBinaryDataHistogram()

	if !h1.Compute(data1) || !h2.Compute(data2) {
		t.Fatal("Failed to compute histograms")
	}

	dist := h1.Distance(h2)
	if dist > 0.1 {
		t.Fatalf("Expected small distance between similar data, got %.5f", dist)
	}

	detector := NewOutlierDetector()
	for range 10 {
		detector.Add(0.01)
		detector.Add(0.02)
	}
	detector.Add(0.99)
	detector.Prepare()

	if detector.DecideOutlier(0.99) <= 0 {
		t.Fatal("Expected 0.99 to be detected as outlier")
	}
}

func TestTargetPoolBasic(t *testing.T) {
	pool := NewTargetPoolWithTargets([]types.Offset{100, 200, 300, 400})
	if pool.Size() != 4 {
		t.Fatalf("Expected size 4, got %d", pool.Size())
	}

	key := pool.KeyForOffset(300)
	if key != 2 {
		t.Fatalf("KeyForOffset(300) = %d, expected 2", key)
	}

	nearKey := pool.KeyForNearestOffset(210)
	if nearKey != 1 {
		t.Fatalf("KeyForNearestOffset(210) = %d, expected 1", nearKey)
	}
}

func TestTargetPoolWithTargetsDoesNotMutateInput(t *testing.T) {
	targets := []types.Offset{30, 10, 20, 10}
	want := slices.Clone(targets)
	pool := NewTargetPoolWithTargets(targets)

	if !slices.Equal(targets, want) {
		t.Fatalf("constructor mutated input: got %v, want %v", targets, want)
	}
	if !slices.Equal(pool.Targets(), []types.Offset{10, 20, 30}) {
		t.Fatalf("unexpected targets: %v", pool.Targets())
	}
}

func TestFindEmbeddedElementsLimit(t *testing.T) {
	detector := func(image []byte) (types.Element, bool) {
		if len(image) == 0 {
			return types.Element{}, false
		}
		return types.Element{Region: types.BufferRegion{Size: 1}, ExeType: types.ExecutableTypeNoOp}, true
	}

	if elements, ok := findEmbeddedElements(make([]byte, 255), detector); !ok || len(elements) != 255 {
		t.Fatalf("255 elements: got %d, ok=%v", len(elements), ok)
	}
	if _, ok := findEmbeddedElements(make([]byte, 256), detector); ok {
		t.Fatal("256 elements should exceed the matcher limit")
	}
}

func TestOffsetMapperDoesNotMutateInput(t *testing.T) {
	equivalences := []types.Equivalence{
		{SrcOffset: 20, DstOffset: 0, Length: 5},
		{SrcOffset: 0, DstOffset: 10, Length: 5},
	}
	want := slices.Clone(equivalences)
	mapper := NewOffsetMapper(equivalences, 32, 32)

	if !slices.Equal(equivalences, want) {
		t.Fatalf("constructor mutated input: got %v, want %v", equivalences, want)
	}
	if got := mapper.Equivalences(); got[0].SrcOffset != 0 || got[1].SrcOffset != 20 {
		t.Fatalf("mapper equivalences were not source-sorted: %v", got)
	}
}
