package matcher

import (
	"slices"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type TargetPool struct {
	types   []types.TypeTag
	targets []types.Offset
}

func NewTargetPool() *TargetPool {
	return &TargetPool{}
}

func NewTargetPoolWithTargets(targets []types.Offset) *TargetPool {
	return NewTargetPoolFromOwnedTargets(slices.Clone(targets))
}

// NewTargetPoolFromOwnedTargets takes ownership of targets. Callers must not
// retain or mutate the slice after passing it here.
func NewTargetPoolFromOwnedTargets(targets []types.Offset) *TargetPool {
	tp := &TargetPool{targets: targets}
	tp.sortAndDeduplicate()
	return tp
}

func (tp *TargetPool) AddType(t types.TypeTag) {
	tp.types = append(tp.types, t)
}

func (tp *TargetPool) Types() []types.TypeTag {
	return tp.types
}

func (tp *TargetPool) Targets() []types.Offset {
	return tp.targets
}

func (tp *TargetPool) Size() int {
	return len(tp.targets)
}

// reserve grows tp.targets to hold n more elements exactly. Letting append
// grow instead overshoots (it doubles, then rounds to a size class), which for
// a pool holding millions of targets leaves a partly-used array of up to twice
// the needed size live alongside the old one.
func (tp *TargetPool) reserve(n int) {
	if cap(tp.targets)-len(tp.targets) >= n {
		return
	}
	grown := make([]types.Offset, len(tp.targets), len(tp.targets)+n)
	copy(grown, tp.targets)
	tp.targets = grown
}

func (tp *TargetPool) InsertTargets(targets []types.Offset) {
	tp.reserve(len(targets))
	tp.targets = append(tp.targets, targets...)
	tp.sortAndDeduplicate()
}

func (tp *TargetPool) InsertReferences(refs []types.Reference) {
	tp.reserve(len(refs))
	for _, ref := range refs {
		tp.targets = append(tp.targets, ref.Target)
	}
	tp.sortAndDeduplicate()
}

func (tp *TargetPool) KeyForOffset(offset types.Offset) uint32 {
	idx := sort.Search(len(tp.targets), func(i int) bool {
		return tp.targets[i] >= offset
	})
	if idx < len(tp.targets) && tp.targets[idx] == offset {
		return uint32(idx)
	}
	return uint32(len(tp.targets))
}

func (tp *TargetPool) KeyForNearestOffset(offset types.Offset) uint32 {
	if len(tp.targets) == 0 {
		return 0
	}
	idx := sort.Search(len(tp.targets), func(i int) bool {
		return tp.targets[i] >= offset
	})
	if idx == 0 {
		return 0
	}
	if idx == len(tp.targets) {
		return uint32(len(tp.targets) - 1)
	}
	d1 := offset - tp.targets[idx-1]
	d2 := tp.targets[idx] - offset
	if d1 <= d2 {
		return uint32(idx - 1)
	}
	return uint32(idx)
}

func (tp *TargetPool) OffsetForKey(key uint32) types.Offset {
	return tp.targets[key]
}

func (tp *TargetPool) KeyIsValid(key uint32) bool {
	return int(key) < len(tp.targets)
}

func (tp *TargetPool) sortAndDeduplicate() {
	slices.Sort(tp.targets)
	if len(tp.targets) > 1 {
		dedup := tp.targets[:1]
		for i := 1; i < len(tp.targets); i++ {
			if tp.targets[i] != dedup[len(dedup)-1] {
				dedup = append(dedup, tp.targets[i])
			}
		}
		tp.targets = dedup
	}
}

// FilterAndProject projects targets from old image space to new image space
// using mapper, dropping targets not covered by any equivalence. Unlike
// InsertTargets, this only sorts (no dedup), matching TargetPool::
// FilterAndProject in the C++ implementation.
func (tp *TargetPool) FilterAndProject(mapper OffsetMapper) {
	tp.targets = mapper.forwardProjectAll(tp.targets, tp.targets[:0])
	slices.Sort(tp.targets)
}
