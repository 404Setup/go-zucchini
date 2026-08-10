package matcher

import (
	"os"
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

// TestProjectionAtMatchesProjection verifies the O(1) cached oracle agrees with
// the reference implementation at every offset of a real binary, both before any
// labels are assigned (iteration 1 conditions) and after (iteration 2).
func TestProjectionAtMatchesProjection(t *testing.T) {
	image, err := os.ReadFile("../../v1.exe")
	if err != nil {
		t.Skipf("v1.exe not available: %v", err)
	}

	d := MakeDisassemblerOfType(image, types.ExecutableTypeWin32X64)
	if d == nil {
		t.Fatal("failed to create disassembler")
	}
	idx := NewImageIndex(image)
	if !idx.Initialize(d) {
		t.Fatal("Initialize failed")
	}

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
	image, err := os.ReadFile("../../v1.exe")
	if err != nil {
		t.Skipf("v1.exe not available: %v", err)
	}
	d := MakeDisassemblerOfType(image, types.ExecutableTypeWin32X64)
	idx := NewImageIndex(image)
	if !idx.Initialize(d) {
		t.Fatal("Initialize failed")
	}

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
