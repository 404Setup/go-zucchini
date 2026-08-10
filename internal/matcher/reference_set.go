package matcher

import (
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type ReferenceSet struct {
	traits     types.ReferenceTypeTraits
	targetPool *TargetPool
	references []types.Reference
}

func NewReferenceSet(traits types.ReferenceTypeTraits, targetPool *TargetPool) *ReferenceSet {
	return &ReferenceSet{
		traits:     traits,
		targetPool: targetPool,
	}
}

func (rs *ReferenceSet) InitReferences(refs []types.Reference) {
	rs.references = make([]types.Reference, len(refs))
	copy(rs.references, refs)
	sort.Slice(rs.references, func(i, j int) bool {
		return rs.references[i].Location < rs.references[j].Location
	})
}

// InitReferencesFromReader drains reader into rs.references directly. Going
// through InitReferences would allocate a second full array and copy into it;
// the slice built here is not shared with any caller, so it can be adopted as
// is. For a large binary this avoids a copy of every reference.
func (rs *ReferenceSet) InitReferencesFromReader(reader types.ReferenceReader, capacityHint int) {
	refs := rs.references[:0]
	if capacityHint > cap(refs) {
		refs = make([]types.Reference, 0, capacityHint)
	}
	for {
		ref, ok := reader.GetNext()
		if !ok {
			break
		}
		refs = append(refs, ref)
	}
	rs.references = refs
	sort.Slice(rs.references, func(i, j int) bool {
		return rs.references[i].Location < rs.references[j].Location
	})
}

func (rs *ReferenceSet) Traits() types.ReferenceTypeTraits {
	return rs.traits
}

func (rs *ReferenceSet) TargetPool() *TargetPool {
	return rs.targetPool
}

func (rs *ReferenceSet) TypeTag() types.TypeTag {
	return rs.traits.TypeTag
}

func (rs *ReferenceSet) PoolTag() types.PoolTag {
	return rs.traits.PoolTag
}

func (rs *ReferenceSet) Width() types.Offset {
	return rs.traits.Width
}

func (rs *ReferenceSet) References() []types.Reference {
	return rs.references
}

func (rs *ReferenceSet) Size() int {
	return len(rs.references)
}

func (rs *ReferenceSet) At(offset types.Offset) types.Reference {
	idx := sort.Search(len(rs.references), func(i int) bool {
		return rs.references[i].Location+rs.traits.Width > offset
	})
	if idx < len(rs.references) {
		return rs.references[idx]
	}
	return types.Reference{}
}
