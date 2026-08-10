package matcher

import (
	"math/bits"

	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/types"
)

type ImageIndex struct {
	image []byte
	// refTypes stores one type tag per reference, in refStart rank order. The
	// coverage and start bitsets locate that entry for any covered image byte,
	// avoiding a type tag allocation proportional to the whole image size.
	refTypes      []types.TypeTag
	targetPools   map[types.PoolTag]*TargetPool
	referenceSets map[types.TypeTag]*ReferenceSet
	// refStart is a bitset marking the first byte of every reference. Only the
	// first byte of a reference is a token, and references of the same type can
	// be adjacent, so this cannot be derived from refTypes alone. Populated by
	// Initialize; nil when there are no references (raw images).
	refStart []uint64
	// refCover marks every byte covered by a reference. It keeps the hot raw-byte
	// path to one bit test; refTypes only needs lookup for actual references.
	refCover []uint64
	// refRank[w] holds the number of refStart bits set in words [0, w), giving
	// O(1) rank queries. The final element is the total reference count. This
	// lets a per-reference array be indexed directly from an image offset.
	refRank []uint32
}

// buildRefRank computes prefix popcounts over refStart. Must run after all
// reference starts are marked.
func (idx *ImageIndex) buildRefRank() {
	if idx.refStart == nil {
		idx.refRank = nil
		return
	}
	idx.refRank = make([]uint32, len(idx.refStart)+1)
	var acc uint32
	for w, word := range idx.refStart {
		idx.refRank[w] = acc
		acc += uint32(bits.OnesCount64(word))
	}
	idx.refRank[len(idx.refStart)] = acc
}

// RefRank returns the number of reference starts strictly before loc. Valid
// only when refStart is populated.
func (idx *ImageIndex) RefRank(loc int) int {
	w := loc >> 6
	mask := (uint64(1) << uint(loc&63)) - 1
	return int(idx.refRank[w]) + bits.OnesCount64(idx.refStart[w]&mask)
}

// RefCount returns the total number of references across all types.
func (idx *ImageIndex) RefCount() int {
	if len(idx.refRank) == 0 {
		return 0
	}
	return int(idx.refRank[len(idx.refRank)-1])
}

func (idx *ImageIndex) markRefStart(loc int) {
	idx.refStart[loc>>6] |= 1 << uint(loc&63)
}

func (idx *ImageIndex) markRefCovered(loc int) {
	idx.refCover[loc>>6] |= 1 << uint(loc&63)
}

func (idx *ImageIndex) isRefCovered(loc int) bool {
	if idx.refCover == nil {
		return false
	}
	return idx.refCover[loc>>6]&(1<<uint(loc&63)) != 0
}

func (idx *ImageIndex) isRefStart(loc int) bool {
	if idx.refStart == nil {
		return false
	}
	return idx.refStart[loc>>6]&(1<<uint(loc&63)) != 0
}

func NewImageIndex(image []byte) *ImageIndex {
	return &ImageIndex{
		image:         image,
		targetPools:   make(map[types.PoolTag]*TargetPool),
		referenceSets: make(map[types.TypeTag]*ReferenceSet),
	}
}

func (idx *ImageIndex) Initialize(d disasm.Disassembler) bool {
	groups := d.MakeReferenceGroups()
	if len(groups) > 0 {
		if idx.refStart == nil {
			idx.refStart = make([]uint64, (len(idx.image)+63)/64)
			idx.refCover = make([]uint64, len(idx.refStart))
		}
	}
	for _, group := range groups {
		poolTag := group.PoolTag()
		if _, ok := idx.targetPools[poolTag]; !ok {
			idx.targetPools[poolTag] = NewTargetPool()
		}
		pool := idx.targetPools[poolTag]
		pool.AddType(group.TypeTag())

		refSet := NewReferenceSet(group.Traits, pool)
		reader := group.GetReader(0, types.Offset(len(idx.image)))

		capacityHint := min(group.ReferenceCountHint, len(idx.image)/max(int(group.Width()), 1))
		refSet.InitReferencesFromReader(reader, capacityHint)

		idx.referenceSets[group.TypeTag()] = refSet

		for _, ref := range refSet.References() {
			w := int(group.Width())
			loc := int(ref.Location)
			if loc+w > len(idx.image) {
				return false
			}
			for i := range w {
				if idx.isRefCovered(loc + i) {
					return false
				}
				idx.markRefCovered(loc + i)
			}
			idx.markRefStart(loc)
		}
	}
	// Populate each pool once. Inserting per reference group repeatedly copies,
	// sorts, and deduplicates a growing target array.
	for _, pool := range idx.targetPools {
		total := 0
		for _, typeTag := range pool.Types() {
			total += len(idx.referenceSets[typeTag].References())
		}
		pool.reserve(total)
		for _, typeTag := range pool.Types() {
			for _, ref := range idx.referenceSets[typeTag].References() {
				pool.targets = append(pool.targets, ref.Target)
			}
		}
		pool.sortAndDeduplicate()
	}
	idx.buildRefRank()
	if count := idx.RefCount(); count > 0 {
		idx.refTypes = make([]types.TypeTag, count)
		for typeTag, refSet := range idx.referenceSets {
			for _, ref := range refSet.References() {
				idx.refTypes[idx.RefRank(int(ref.Location))] = typeTag
			}
		}
	}
	return true
}

func (idx *ImageIndex) Size() int {
	return len(idx.image)
}

func (idx *ImageIndex) IsToken(location types.Offset) bool {
	loc := int(location)
	if loc >= len(idx.image) {
		return false
	}
	if !idx.isRefCovered(loc) {
		return true
	}
	// |location| points into a Reference: only its first byte is a token. This
	// must not be inferred from typeTags, since two references of the same type
	// can be adjacent.
	return idx.isRefStart(loc)
}

func (idx *ImageIndex) IsReference(location types.Offset) bool {
	loc := int(location)
	if loc >= len(idx.image) {
		return false
	}
	return idx.isRefCovered(loc)
}

func (idx *ImageIndex) LookupType(location types.Offset) types.TypeTag {
	loc := int(location)
	if loc >= len(idx.image) || !idx.isRefCovered(loc) {
		return types.NoTypeTag
	}
	rank := idx.RefRank(loc)
	if !idx.isRefStart(loc) {
		rank--
	}
	return idx.refTypes[rank]
}

func (idx *ImageIndex) GetRawValue(location types.Offset) byte {
	return idx.image[location]
}

func (idx *ImageIndex) TargetPools() map[types.PoolTag]*TargetPool {
	return idx.targetPools
}

func (idx *ImageIndex) ReferenceSets() map[types.TypeTag]*ReferenceSet {
	return idx.referenceSets
}

func (idx *ImageIndex) Pool(poolTag types.PoolTag) *TargetPool {
	return idx.targetPools[poolTag]
}

func (idx *ImageIndex) Refs(typeTag types.TypeTag) *ReferenceSet {
	return idx.referenceSets[typeTag]
}

func (idx *ImageIndex) TypeCount() int {
	if len(idx.referenceSets) == 0 {
		return 0
	}
	maxKey := 0
	for tag := range idx.referenceSets {
		if int(tag) > maxKey {
			maxKey = int(tag)
		}
	}
	return maxKey + 1
}

func (idx *ImageIndex) PoolCount() int {
	if len(idx.targetPools) == 0 {
		return 0
	}
	maxKey := 0
	for tag := range idx.targetPools {
		if int(tag) > maxKey {
			maxKey = int(tag)
		}
	}
	return maxKey + 1
}
