package matcher

import (
	"math"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type Association struct {
	Other    uint32
	Affinity float64
}

type TargetsAffinity struct {
	forwardAssociation  []Association
	backwardAssociation []Association
}

func NewTargetsAffinity() *TargetsAffinity {
	return &TargetsAffinity{}
}

// resetAssociations returns a zeroed []Association of length n, reusing buf's
// array when it is large enough.
func resetAssociations(buf []Association, n int) []Association {
	if cap(buf) < n {
		return make([]Association, n)
	}
	buf = buf[:n]
	for i := range buf {
		buf[i] = Association{}
	}
	return buf
}

func (ta *TargetsAffinity) InferFromSimilarities(
	eqMap *EquivalenceMap,
	oldTargets []types.Offset,
	newTargets []types.Offset,
) {
	ta.forwardAssociation = resetAssociations(ta.forwardAssociation, len(oldTargets))
	ta.backwardAssociation = resetAssociations(ta.backwardAssociation, len(newTargets))

	if len(oldTargets) == 0 || len(newTargets) == 0 {
		return
	}

	newKey := 0
	for _, cand := range eqMap.Candidates() {
		eq := cand.Eq

		for newKey < len(newTargets) && newTargets[newKey] < eq.DstOffset {
			newKey++
		}

		for newKey < len(newTargets) && newTargets[newKey] < eq.DstEnd() {
			if ta.backwardAssociation[newKey].Affinity >= cand.Similarity {
				newKey++
				continue
			}

			oldTarget := newTargets[newKey] - eq.DstOffset + eq.SrcOffset
			oldIdx := sort.Search(len(oldTargets), func(i int) bool {
				return oldTargets[i] >= oldTarget
			})
			if oldIdx < len(oldTargets) && oldTargets[oldIdx] == oldTarget {
				oldKey := uint32(oldIdx)
				if cand.Similarity > ta.forwardAssociation[oldKey].Affinity {
					if ta.forwardAssociation[oldKey].Affinity > 0.0 {
						ta.backwardAssociation[ta.forwardAssociation[oldKey].Other] = Association{}
					}
					if ta.backwardAssociation[newKey].Affinity > 0.0 {
						ta.forwardAssociation[ta.backwardAssociation[newKey].Other] = Association{}
					}
					ta.forwardAssociation[oldKey] = Association{Other: uint32(newKey), Affinity: cand.Similarity}
					ta.backwardAssociation[newKey] = Association{Other: oldKey, Affinity: cand.Similarity}
				}
			}
			newKey++
		}
	}
}

func (ta *TargetsAffinity) AssignLabels(
	minAffinity float64,
	oldLabels *[]uint32,
	newLabels *[]uint32,
) uint32 {
	*oldLabels = resetUint32s(*oldLabels, len(ta.forwardAssociation))
	*newLabels = resetUint32s(*newLabels, len(ta.backwardAssociation))

	label := uint32(1)
	for i, assoc := range ta.forwardAssociation {
		if assoc.Affinity >= minAffinity {
			(*oldLabels)[i] = label
			(*newLabels)[assoc.Other] = label
			label++
		}
	}
	return label
}

func resetUint32s(buf []uint32, n int) []uint32 {
	if cap(buf) < n {
		return make([]uint32, n)
	}
	buf = buf[:n]
	clear(buf)
	return buf
}

func (ta *TargetsAffinity) AffinityBetween(oldKey, newKey uint32) float64 {
	var fwdAffinity, bwdAffinity float64
	if int(oldKey) < len(ta.forwardAssociation) {
		assoc := ta.forwardAssociation[oldKey]
		if assoc.Affinity > 0 && assoc.Other == newKey {
			return assoc.Affinity
		}
		fwdAffinity = assoc.Affinity
	}
	if int(newKey) < len(ta.backwardAssociation) {
		bwdAffinity = ta.backwardAssociation[newKey].Affinity
	}
	return -math.Max(fwdAffinity, bwdAffinity)
}
