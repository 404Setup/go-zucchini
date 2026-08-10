package matcher

import (
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

type sliceReferenceReader struct {
	refs []types.Reference
	next int
}

func (r *sliceReferenceReader) GetNext() (types.Reference, bool) {
	if r.next == len(r.refs) {
		return types.Reference{}, false
	}
	ref := r.refs[r.next]
	r.next++
	return ref, true
}

func TestInitReferencesFromReaderUsesCapacityHint(t *testing.T) {
	refs := []types.Reference{
		{Location: 8, Target: 80},
		{Location: 2, Target: 20},
		{Location: 5, Target: 50},
	}
	set := NewReferenceSet(types.ReferenceTypeTraits{Width: 4}, NewTargetPool())
	set.InitReferencesFromReader(&sliceReferenceReader{refs: refs}, len(refs))

	if cap(set.references) != len(refs) {
		t.Fatalf("reference capacity = %d, want %d", cap(set.references), len(refs))
	}
	for i, want := range []types.Offset{2, 5, 8} {
		if set.references[i].Location != want {
			t.Fatalf("reference %d location = %d, want %d", i, set.references[i].Location, want)
		}
	}
}
