package matcher

import (
	"testing"

	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/types"
)

// TestProjectionAtMatchesProjection verifies the O(1) cached oracle agrees with
// the reference implementation at every offset, both before any labels are
// assigned (iteration 1 conditions) and after (iteration 2).
func TestProjectionAtMatchesProjection(t *testing.T) {
	idx := newProjectionTestIndex(t)

	check := func(name string, ev *EncodedView) {
		ev.BuildProjectionCache()
		for i := 0; i < ev.Size(); i++ {
			want := ev.Projection(types.Offset(i))
			got := ev.ProjectionAt(types.Offset(i))
			if want != got {
				t.Fatalf("%s: offset %d: ProjectionAt=%d, Projection=%d", name, i, got, want)
			}
		}
	}

	check("unlabeled", NewEncodedView(idx))

	ev := NewEncodedView(idx)
	for poolTag, pool := range idx.TargetPools() {
		labels := make([]uint32, pool.Size())
		for i := range labels {
			labels[i] = uint32(i + 1)
		}
		ev.SetLabels(poolTag, labels, pool.Size()+1)
	}
	check("labeled", ev)
}

// TestRefRankConsistency checks the rank structure against a direct count.
func TestRefRankConsistency(t *testing.T) {
	idx := newProjectionTestIndex(t)

	total := 0
	for _, refSet := range idx.ReferenceSets() {
		total += refSet.Size()
	}
	if idx.RefCount() != total {
		t.Fatalf("RefCount=%d, sum of reference sets=%d", idx.RefCount(), total)
	}

	running := 0
	for i := 0; i < idx.Size(); i++ {
		if r := idx.RefRank(i); r != running {
			t.Fatalf("offset %d: RefRank=%d, expected %d", i, r, running)
		}
		if idx.isRefStart(i) {
			running++
		}
	}
	if running != total {
		t.Fatalf("counted %d reference starts, expected %d", running, total)
	}
}

type projectionTestDisassembler struct {
	image []byte
	refs  []types.Reference
}

func (d *projectionTestDisassembler) GetExeType() types.ExecutableType {
	return types.ExecutableTypeNoOp
}
func (d *projectionTestDisassembler) GetExeTypeString() string { return "projection-test" }
func (d *projectionTestDisassembler) Image() []byte            { return d.image }
func (d *projectionTestDisassembler) Size() int                { return len(d.image) }
func (d *projectionTestDisassembler) NumEquivalenceIterations() int {
	return 2
}
func (d *projectionTestDisassembler) Parse() bool { return true }
func (d *projectionTestDisassembler) MakeReferenceGroups() []disasm.ReferenceGroup {
	return []disasm.ReferenceGroup{{
		Traits:             types.ReferenceTypeTraits{Width: 4, TypeTag: 1, PoolTag: 1},
		ReferenceCountHint: len(d.refs),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			refs := make([]types.Reference, 0, len(d.refs))
			for _, ref := range d.refs {
				if ref.Location >= lower && ref.Location < upper {
					refs = append(refs, ref)
				}
			}
			return &projectionTestReader{refs: refs}
		},
		WriterFactory: func([]byte) types.ReferenceWriter {
			return disasm.NewEmptyReferenceWriter()
		},
	}}
}

type projectionTestReader struct {
	refs []types.Reference
	pos  int
}

func (r *projectionTestReader) GetNext() (types.Reference, bool) {
	if r.pos == len(r.refs) {
		return types.Reference{}, false
	}
	ref := r.refs[r.pos]
	r.pos++
	return ref, true
}

func newProjectionTestIndex(t *testing.T) *ImageIndex {
	t.Helper()
	image := make([]byte, 192)
	for i := range image {
		image[i] = byte(i*37 + i/11)
	}
	d := &projectionTestDisassembler{image: image, refs: []types.Reference{
		{Location: 3, Target: 40},
		{Location: 31, Target: 80},
		{Location: 64, Target: 120},
		{Location: 95, Target: 40},
		{Location: 127, Target: 160},
	}}
	idx := NewImageIndex(image)
	if !idx.Initialize(d) {
		t.Fatal("Initialize failed for in-memory reference fixture")
	}
	return idx
}

func TestReferenceTypeByRank(t *testing.T) {
	idx := NewImageIndex(make([]byte, 12))
	idx.refStart = make([]uint64, 1)
	idx.refCover = make([]uint64, 1)
	idx.markRefStart(3)
	for i := 3; i < 8; i++ {
		idx.markRefCovered(i)
	}
	idx.buildRefRank()
	idx.refTypes = []types.TypeTag{42}

	for i := 3; i < 8; i++ {
		if got := idx.LookupType(types.Offset(i)); got != 42 {
			t.Fatalf("LookupType(%d)=%d, want 42", i, got)
		}
	}
	if got := idx.LookupType(2); got != types.NoTypeTag {
		t.Fatalf("LookupType(2)=%d, want NoTypeTag", got)
	}
}
