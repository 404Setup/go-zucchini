package matcher

import (
	"github.com/404Setup/go-zucchini/internal/sais"
	"github.com/404Setup/go-zucchini/internal/types"
)

const (
	ReferencePaddingProjection = 256
	BaseReferenceProjection    = 257
)

type PoolInfo struct {
	labels []uint32
	bound  int
}

type EncodedView struct {
	imageIndex *ImageIndex
	poolInfos  map[types.PoolTag]*PoolInfo
	// refProj holds the projection value of each reference, indexed by the
	// reference's rank in ImageIndex.refStart. Together with that bitset it lets
	// ProjectionAt answer in O(1) without materializing a projection value for
	// every byte of the image, which for a large binary is two orders of
	// magnitude more memory. Built by BuildProjectionCache.
	refProj []uint32
}

func NewEncodedView(imageIndex *ImageIndex) *EncodedView {
	return &EncodedView{
		imageIndex: imageIndex,
		poolInfos:  make(map[types.PoolTag]*PoolInfo),
	}
}

// BuildProjectionCache precomputes per-reference projections so ProjectionAt
// becomes O(1). Must be called after all SetLabels calls, since projections
// depend on labels. Costs one pass over references rather than over the image.
func (ev *EncodedView) BuildProjectionCache() {
	n := ev.imageIndex.RefCount()
	if n == 0 {
		ev.refProj = nil
		return
	}
	if len(ev.refProj) != n {
		ev.refProj = make([]uint32, n)
	}
	typeCount := uint32(ev.imageIndex.TypeCount())
	for typeTag, refSet := range ev.imageIndex.referenceSets {
		pool := refSet.TargetPool()
		pInfo := ev.poolInfos[refSet.PoolTag()]
		base := uint32(typeTag) + uint32(BaseReferenceProjection)
		for _, ref := range refSet.References() {
			label := uint32(0)
			if pInfo != nil {
				if targetKey := pool.KeyForOffset(ref.Target); int(targetKey) < len(pInfo.labels) {
					label = pInfo.labels[targetKey]
				}
			}
			ev.refProj[ev.imageIndex.RefRank(int(ref.Location))] = label*typeCount + base
		}
	}
}

// QueryAt lets *EncodedView act as a lazy query string for suffix array lookup,
// so the "new" side never needs a materialized projection array.
func (ev *EncodedView) QueryAt(i int) uint32 {
	if uint(i) >= uint(len(ev.imageIndex.image)) {
		return 0
	}
	if ev.imageIndex.refCover == nil || ev.imageIndex.refCover[i>>6]&(1<<uint(i&63)) == 0 {
		return uint32(ev.imageIndex.image[i])
	}
	return ev.referenceProjection(i)
}

// ProjectionAt returns the same value as Projection, but in O(1) using the
// cache built by BuildProjectionCache.
func (ev *EncodedView) ProjectionAt(location types.Offset) uint32 {
	return ev.QueryAt(int(location))
}

func (ev *EncodedView) referenceProjection(loc int) uint32 {
	if ev.imageIndex.refStart[loc>>6]&(1<<uint(loc&63)) == 0 {
		return ReferencePaddingProjection
	}
	return ev.refProj[ev.imageIndex.RefRank(loc)]
}

func (ev *EncodedView) ImageIndex() *ImageIndex {
	return ev.imageIndex
}

func (ev *EncodedView) SuffixSource() *sais.ProjectionSource {
	idx := ev.imageIndex
	return sais.NewProjectionSource(idx.image, idx.refStart, idx.refCover, idx.refRank, ev.refProj)
}

func (ev *EncodedView) Size() int {
	return ev.imageIndex.Size()
}

func (ev *EncodedView) Projection(location types.Offset) uint32 {
	loc := int(location)
	if loc >= ev.imageIndex.Size() {
		return 0
	}
	typeTag := ev.imageIndex.LookupType(location)
	if typeTag == types.NoTypeTag {
		return uint32(ev.imageIndex.GetRawValue(location))
	}

	refSet := ev.imageIndex.Refs(typeTag)
	ref := refSet.At(location)

	if ref.Location != location {
		return ReferencePaddingProjection
	}

	poolTag := refSet.PoolTag()
	targetKey := refSet.TargetPool().KeyForOffset(ref.Target)

	label := uint32(0)
	if pInfo, ok := ev.poolInfos[poolTag]; ok {
		if int(targetKey) < len(pInfo.labels) {
			label = pInfo.labels[targetKey]
		}
	}

	return label*uint32(ev.imageIndex.TypeCount()) + uint32(typeTag) + uint32(BaseReferenceProjection)
}

func (ev *EncodedView) Cardinality() int {
	maxBound := 0
	for _, pInfo := range ev.poolInfos {
		if pInfo.bound > maxBound {
			maxBound = pInfo.bound
		}
	}
	return maxBound*ev.imageIndex.TypeCount() + BaseReferenceProjection
}

func (ev *EncodedView) SetLabels(pool types.PoolTag, labels []uint32, bound int) {
	ev.poolInfos[pool] = &PoolInfo{
		labels: labels,
		bound:  bound,
	}
}
