package matcher

import (
	"math"
	"slices"
	"sort"

	"github.com/404Setup/go-zucchini/internal/sais"
	"github.com/404Setup/go-zucchini/internal/types"
)

var MismatchFatal = math.Inf(-1)

const (
	SeedSelectionTotalVisitLengthQuota = 1 << 18
	BackwardsExtendLimit               = 1 << 16
)

func GetTokenSimilarity(
	oldIdx *ImageIndex,
	newIdx *ImageIndex,
	affinities []TargetsAffinity,
	src, dst types.Offset,
) float64 {
	oldType := oldIdx.LookupType(src)
	newType := newIdx.LookupType(dst)
	if oldType != newType {
		return MismatchFatal
	}

	if oldType == types.NoTypeTag {
		if oldIdx.GetRawValue(src) == newIdx.GetRawValue(dst) {
			return 1.0
		}
		return -1.5
	}

	oldRefSet := oldIdx.Refs(oldType)
	newRefSet := newIdx.Refs(newType)
	oldRef := oldRefSet.At(src)
	newRef := newRefSet.At(dst)
	poolTag := oldRefSet.PoolTag()

	oldKey := oldRefSet.TargetPool().KeyForOffset(oldRef.Target)
	newKey := newRefSet.TargetPool().KeyForOffset(newRef.Target)

	affinity := 0.0
	if int(poolTag) < len(affinities) {
		affinity = affinities[poolTag].AffinityBetween(oldKey, newKey)
	}

	if affinity == 0.0 {
		return 0.5 * float64(oldRefSet.Width())
	}
	if affinity > 0.0 {
		return float64(oldRefSet.Width())
	}
	return -2.0
}

func GetEquivalenceSimilarity(
	oldIdx *ImageIndex,
	newIdx *ImageIndex,
	affinities []TargetsAffinity,
	eq types.Equivalence,
) float64 {
	similarity := 0.0
	for k := types.Offset(0); k < eq.Length; k++ {
		if !newIdx.IsToken(eq.DstOffset + k) {
			continue
		}
		sim := GetTokenSimilarity(oldIdx, newIdx, affinities, eq.SrcOffset+k, eq.DstOffset+k)
		if math.IsInf(sim, -1) {
			return MismatchFatal
		}
		similarity += sim
	}
	return similarity
}

func ExtendEquivalenceForward(
	oldIdx *ImageIndex,
	newIdx *ImageIndex,
	affinities []TargetsAffinity,
	candidate types.EquivalenceCandidate,
	minSimilarity float64,
) types.EquivalenceCandidate {
	eq := candidate.Eq
	bestK := eq.Length
	currentSim := candidate.Similarity
	bestSim := currentSim
	currentPenalty := minSimilarity

	for k := bestK; int(eq.SrcOffset+k) < oldIdx.Size() && int(eq.DstOffset+k) < newIdx.Size(); k++ {
		if oldIdx.LookupType(eq.SrcOffset+k) != newIdx.LookupType(eq.DstOffset+k) {
			break
		}
		if !newIdx.IsToken(eq.DstOffset + k) {
			if bestK == k {
				bestK = k + 1
			}
			continue
		}

		sim := GetTokenSimilarity(oldIdx, newIdx, affinities, eq.SrcOffset+k, eq.DstOffset+k)
		currentSim += sim
		currentPenalty = math.Max(0.0, currentPenalty) - sim

		if currentSim < 0.0 || currentPenalty >= minSimilarity {
			break
		}
		if currentSim >= bestSim {
			bestSim = currentSim
			bestK = k + 1
		}
	}
	eq.Length = bestK
	return types.EquivalenceCandidate{Eq: eq, Similarity: bestSim}
}

func ExtendEquivalenceBackward(
	oldIdx *ImageIndex,
	newIdx *ImageIndex,
	affinities []TargetsAffinity,
	candidate types.EquivalenceCandidate,
	minSimilarity float64,
) types.EquivalenceCandidate {
	eq := candidate.Eq
	var bestK types.Offset = 0
	currentSim := candidate.Similarity
	bestSim := currentSim
	currentPenalty := 0.0

	kMin := min(eq.SrcOffset, eq.DstOffset)
	if types.Offset(BackwardsExtendLimit) < kMin {
		kMin = types.Offset(BackwardsExtendLimit)
	}

	for k := types.Offset(1); k <= kMin; k++ {
		if oldIdx.LookupType(eq.SrcOffset-k) != newIdx.LookupType(eq.DstOffset-k) {
			break
		}
		if !newIdx.IsToken(eq.DstOffset - k) {
			continue
		}

		sim := GetTokenSimilarity(oldIdx, newIdx, affinities, eq.SrcOffset-k, eq.DstOffset-k)
		currentSim += sim
		currentPenalty = math.Max(0.0, currentPenalty) - sim

		if currentSim < 0.0 || currentPenalty >= minSimilarity {
			break
		}
		if currentSim >= bestSim {
			bestSim = currentSim
			bestK = k
		}
	}

	eq.DstOffset -= bestK
	eq.SrcOffset -= bestK
	eq.Length += bestK
	return types.EquivalenceCandidate{Eq: eq, Similarity: bestSim}
}

func VisitEquivalenceSeed(
	oldIdx *ImageIndex,
	newIdx *ImageIndex,
	affinities []TargetsAffinity,
	src, dst types.Offset,
	minSimilarity float64,
) types.EquivalenceCandidate {
	cand := types.EquivalenceCandidate{
		Eq:         types.Equivalence{SrcOffset: src, DstOffset: dst, Length: 0},
		Similarity: 0.0,
	}
	if !oldIdx.IsToken(src) {
		return cand
	}
	cand = ExtendEquivalenceForward(oldIdx, newIdx, affinities, cand, minSimilarity)
	if cand.Similarity < minSimilarity {
		return cand
	}
	return ExtendEquivalenceBackward(oldIdx, newIdx, affinities, cand, minSimilarity)
}

type OffsetMapper struct {
	equivalences []types.Equivalence
	oldImageSize types.Offset
	newImageSize types.Offset
}

func NewOffsetMapper(equivalences []types.Equivalence, oldImageSize, newImageSize types.Offset) *OffsetMapper {
	return NewOffsetMapperFromOwnedEquivalences(slices.Clone(equivalences), oldImageSize, newImageSize)
}

// NewOffsetMapperFromOwnedEquivalences takes ownership of equivalences.
func NewOffsetMapperFromOwnedEquivalences(equivalences []types.Equivalence, oldImageSize, newImageSize types.Offset) *OffsetMapper {
	PruneEquivalencesAndSortBySource(&equivalences)
	return &OffsetMapper{
		equivalences: equivalences,
		oldImageSize: oldImageSize,
		newImageSize: newImageSize,
	}
}

func (m *OffsetMapper) Equivalences() []types.Equivalence {
	return m.equivalences
}

// ForwardProjectAll projects each offset in sorted slice offsets from old
// image space to new image space, dropping any offset not covered by an
// equivalence. Unlike ExtendedForwardProject, this never falls back to the
// nearest equivalence: offsets in gaps are discarded, matching
// OffsetMapper::ForwardProjectAll in the C++ implementation.
func (m *OffsetMapper) ForwardProjectAll(offsets []types.Offset) []types.Offset {
	return m.forwardProjectAll(offsets, make([]types.Offset, 0, len(offsets)))
}

func (m *OffsetMapper) forwardProjectAll(offsets, projected []types.Offset) []types.Offset {
	idx := 0
	for _, src := range offsets {
		for idx < len(m.equivalences) && m.equivalences[idx].SrcEnd() <= src {
			idx++
		}
		if idx < len(m.equivalences) && m.equivalences[idx].SrcOffset <= src {
			eq := m.equivalences[idx]
			projected = append(projected, src-eq.SrcOffset+eq.DstOffset)
		}
	}
	return projected
}

func (m *OffsetMapper) ExtendedForwardProject(offset types.Offset) types.Offset {
	if len(m.equivalences) == 0 {
		return types.InvalidOffset
	}
	if offset < m.oldImageSize {
		idx := sort.Search(len(m.equivalences), func(i int) bool {
			return m.equivalences[i].SrcOffset > offset
		})
		if idx > 0 && (idx == len(m.equivalences) || offset < m.equivalences[idx-1].SrcEnd() ||
			(offset-m.equivalences[idx-1].SrcEnd() < m.equivalences[idx].SrcOffset-offset)) {
			idx--
		}
		if idx >= len(m.equivalences) {
			idx = len(m.equivalences) - 1
		}
		eq := m.equivalences[idx]
		delta := max(int64(offset)-int64(eq.SrcOffset)+int64(eq.DstOffset), 0)
		if delta >= int64(m.newImageSize) {
			delta = int64(m.newImageSize - 1)
		}
		return types.Offset(delta)
	}
	delta := offset - m.oldImageSize
	if delta < types.OffsetBound-m.newImageSize {
		return m.newImageSize + delta
	}
	return types.OffsetBound - 1
}

func PruneEquivalencesAndSortBySource(equivalences *[]types.Equivalence) {
	eqs := *equivalences
	sort.Slice(eqs, func(i, j int) bool {
		if eqs[i].SrcOffset != eqs[j].SrcOffset {
			return eqs[i].SrcOffset < eqs[j].SrcOffset
		}
		if eqs[i].Length != eqs[j].Length {
			return eqs[i].Length > eqs[j].Length
		}
		return eqs[i].DstOffset < eqs[j].DstOffset
	})

	for i := 0; i < len(eqs); i++ {
		if eqs[i].Length == 0 {
			continue
		}
		currentEnd := eqs[i].SrcEnd()
		nextIsReaper := false
		nextIdx := i + 1

		for ; nextIdx < len(eqs); nextIdx++ {
			if eqs[nextIdx].SrcOffset >= currentEnd {
				break
			}
			if eqs[i].Length < eqs[nextIdx].Length {
				delta := currentEnd - eqs[nextIdx].SrcOffset
				if delta < eqs[i].Length {
					eqs[i].Length -= delta
				} else {
					eqs[i].Length = 0
				}
				nextIsReaper = true
				break
			}
		}

		if nextIsReaper {
			for r := i + 1; r < nextIdx; r++ {
				eqs[r].Length = 0
			}
			i = nextIdx - 1
		} else {
			for r := i + 1; r < nextIdx; r++ {
				delta := currentEnd - eqs[r].SrcOffset
				capped := min(delta, eqs[r].Length)
				eqs[r].Length -= capped
				eqs[r].SrcOffset = currentEnd
				eqs[r].DstOffset += capped
			}
		}
	}

	filtered := eqs[:0]
	for _, eq := range eqs {
		if eq.Length > 0 {
			filtered = append(filtered, eq)
		}
	}
	*equivalences = filtered
}

type EquivalenceMap struct {
	candidates []types.EquivalenceCandidate
}

type projectionSlice []uint32

func (s projectionSlice) Size() int            { return len(s) }
func (s projectionSlice) QueryAt(i int) uint32 { return s[i] }

func NewEquivalenceMap() *EquivalenceMap {
	return &EquivalenceMap{}
}

func (m *EquivalenceMap) Candidates() []types.EquivalenceCandidate {
	return m.candidates
}

func (m *EquivalenceMap) Build(
	oldSA []uint32,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	oldProj := make([]uint32, oldView.Size())
	for i := 0; i < oldView.Size(); i++ {
		oldProj[i] = oldView.Projection(types.Offset(i))
	}

	m.BuildWithProjections(oldSA, oldProj, oldView, newView, affinities, minSimilarity)
}

func (m *EquivalenceMap) BuildWithProjections(
	oldSA []uint32,
	oldProj []uint32,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	m.BuildWithSource(oldSA, projectionSlice(oldProj), oldView, newView, affinities, minSimilarity)
}

func (m *EquivalenceMap) BuildWithEncodedViews(
	oldSA []uint32,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	m.createCandidatesEncoded(oldSA, oldView, newView, affinities, minSimilarity)
	m.sortByDestination()
	m.prune(oldView, newView, affinities, minSimilarity)
}

func (m *EquivalenceMap) BuildWithSource(
	oldSA []uint32,
	oldSource sais.Uint32Source,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	m.createCandidates(oldSA, oldSource, oldView, newView, affinities, minSimilarity)
	m.sortByDestination()
	m.prune(oldView, newView, affinities, minSimilarity)
}

func (m *EquivalenceMap) createCandidates(
	oldSA []uint32,
	oldSource sais.Uint32Source,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	m.candidates = nil
	dstOffset := types.Offset(0)

	newView.BuildProjectionCache()
	newEnd := newView.Size()

	for int(dstOffset) < newView.Size() {
		if !newView.ImageIndex().IsToken(dstOffset) {
			dstOffset++
			continue
		}

		matchIdx := sais.SuffixLowerBoundSource(oldSA, oldSource, newView, int(dstOffset), newEnd)

		nextDstOffset := dstOffset + 1
		bestSim := minSimilarity
		var totalVisitLength uint64 = 0
		bestCandidate := types.EquivalenceCandidate{
			Eq:         types.Equivalence{SrcOffset: 0, DstOffset: 0, Length: 0},
			Similarity: 0.0,
		}

		for idx := matchIdx; idx < len(oldSA); idx++ {
			cand := VisitEquivalenceSeed(oldView.ImageIndex(), newView.ImageIndex(), affinities, types.Offset(oldSA[idx]), dstOffset, minSimilarity)
			if cand.Similarity > bestSim {
				bestCandidate = cand
				bestSim = cand.Similarity
				nextDstOffset = cand.Eq.DstEnd()
				totalVisitLength += uint64(cand.Eq.Length)
				if totalVisitLength > SeedSelectionTotalVisitLengthQuota {
					break
				}
			} else {
				break
			}
		}

		totalVisitLength = 0
		for idx := matchIdx - 1; idx >= 0; idx-- {
			//nolint:staticcheck
			cand := VisitEquivalenceSeed(oldView.ImageIndex(), newView.ImageIndex(), affinities, types.Offset(oldSA[idx]), dstOffset, minSimilarity)
			if cand.Similarity > bestSim {
				bestCandidate = cand
				bestSim = cand.Similarity
				nextDstOffset = cand.Eq.DstEnd()
				totalVisitLength += uint64(cand.Eq.Length)
				if totalVisitLength > SeedSelectionTotalVisitLengthQuota {
					break
				}
			} else {
				break
			}
		}

		if bestCandidate.Similarity >= minSimilarity {
			m.candidates = append(m.candidates, bestCandidate)
		}
		dstOffset = nextDstOffset
	}
}

func (m *EquivalenceMap) createCandidatesEncoded(
	oldSA []uint32,
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	m.candidates = nil
	dstOffset := types.Offset(0)
	newView.BuildProjectionCache()

	for int(dstOffset) < newView.Size() {
		if !newView.ImageIndex().IsToken(dstOffset) {
			dstOffset++
			continue
		}

		matchIdx := suffixLowerBoundEncoded(oldSA, oldView, newView, int(dstOffset))
		nextDstOffset := dstOffset + 1
		bestSim := minSimilarity
		var totalVisitLength uint64
		bestCandidate := types.EquivalenceCandidate{}

		for idx := matchIdx; idx < len(oldSA); idx++ {
			cand := VisitEquivalenceSeed(oldView.ImageIndex(), newView.ImageIndex(), affinities, types.Offset(oldSA[idx]), dstOffset, minSimilarity)
			if cand.Similarity <= bestSim {
				break
			}
			bestCandidate = cand
			bestSim = cand.Similarity
			nextDstOffset = cand.Eq.DstEnd()
			totalVisitLength += uint64(cand.Eq.Length)
			if totalVisitLength > SeedSelectionTotalVisitLengthQuota {
				break
			}
		}

		totalVisitLength = 0
		for idx := matchIdx - 1; idx >= 0; idx-- {
			//nolint:staticcheck
			cand := VisitEquivalenceSeed(oldView.ImageIndex(), newView.ImageIndex(), affinities, types.Offset(oldSA[idx]), dstOffset, minSimilarity)
			if cand.Similarity <= bestSim {
				break
			}
			bestCandidate = cand
			bestSim = cand.Similarity
			nextDstOffset = cand.Eq.DstEnd()
			totalVisitLength += uint64(cand.Eq.Length)
			if totalVisitLength > SeedSelectionTotalVisitLengthQuota {
				break
			}
		}

		if bestCandidate.Similarity >= minSimilarity {
			m.candidates = append(m.candidates, bestCandidate)
		}
		dstOffset = nextDstOffset
	}
}

func (m *EquivalenceMap) sortByDestination() {
	sort.Slice(m.candidates, func(i, j int) bool {
		return m.candidates[i].Eq.DstOffset < m.candidates[j].Eq.DstOffset
	})
}

func (m *EquivalenceMap) prune(
	oldView *EncodedView,
	newView *EncodedView,
	affinities []TargetsAffinity,
	minSimilarity float64,
) {
	for i := 0; i < len(m.candidates); i++ {
		if m.candidates[i].Similarity < minSimilarity {
			continue
		}
		nextIsReaper := false
		nextIdx := i + 1

		for ; nextIdx < len(m.candidates); nextIdx++ {
			if m.candidates[nextIdx].Eq.DstOffset >= m.candidates[i].Eq.DstEnd() {
				break
			}
			if m.candidates[i].Similarity < m.candidates[nextIdx].Similarity {
				delta := m.candidates[i].Eq.DstEnd() - m.candidates[nextIdx].Eq.DstOffset
				if delta < m.candidates[i].Eq.Length {
					m.candidates[i].Eq.Length -= delta
				} else {
					m.candidates[i].Eq.Length = 0
				}
				m.candidates[i].Similarity = GetEquivalenceSimilarity(
					oldView.ImageIndex(), newView.ImageIndex(), affinities, m.candidates[i].Eq,
				)
				nextIsReaper = true
				break
			}
		}

		if nextIsReaper {
			for r := i + 1; r < nextIdx; r++ {
				m.candidates[r].Eq.Length = 0
				m.candidates[r].Similarity = 0
			}
			i = nextIdx - 1
		} else {
			for r := i + 1; r < nextIdx; r++ {
				delta := m.candidates[i].Eq.DstEnd() - m.candidates[r].Eq.DstOffset
				capped := min(delta, m.candidates[r].Eq.Length)
				m.candidates[r].Eq.Length -= capped
				m.candidates[r].Eq.SrcOffset += delta
				m.candidates[r].Eq.DstOffset += delta
				m.candidates[r].Similarity = GetEquivalenceSimilarity(
					oldView.ImageIndex(), newView.ImageIndex(), affinities, m.candidates[r].Eq,
				)
			}
		}
	}

	filtered := m.candidates[:0]
	for _, cand := range m.candidates {
		if cand.Similarity >= minSimilarity {
			filtered = append(filtered, cand)
		}
	}
	m.candidates = filtered
}

const (
	MinEquivalenceSimilarity = 12.0
	MinLabelAffinity         = 64.0
)

func CreateEquivalenceMap(oldIdx, newIdx *ImageIndex, numIterations int) *EquivalenceMap {
	poolCount := oldIdx.PoolCount()
	affinities := make([]TargetsAffinity, poolCount)

	eqMap := NewEquivalenceMap()

	var sa []uint32
	var saWorkspace sais.Workspace
	oldLabelsByPool := make([][]uint32, poolCount)
	newLabelsByPool := make([][]uint32, poolCount)
	oldView := NewEncodedView(oldIdx)
	newView := NewEncodedView(newIdx)

	var poolTags []types.PoolTag
	for tag := range oldIdx.TargetPools() {
		poolTags = append(poolTags, tag)
	}
	slices.Sort(poolTags)

	for range numIterations {
		for _, poolTag := range poolTags {
			oldTargets := oldIdx.TargetPools()[poolTag]
			newPool := newIdx.Pool(poolTag)
			if newPool != nil && int(poolTag) < len(affinities) {
				affinities[int(poolTag)].InferFromSimilarities(
					eqMap, oldTargets.Targets(), newPool.Targets(),
				)

				labelBound := affinities[int(poolTag)].AssignLabels(
					MinLabelAffinity, &oldLabelsByPool[int(poolTag)], &newLabelsByPool[int(poolTag)],
				)
				oldView.SetLabels(poolTag, oldLabelsByPool[int(poolTag)], int(labelBound))
				newView.SetLabels(poolTag, newLabelsByPool[int(poolTag)], int(labelBound))
			}
		}

		oldView.BuildProjectionCache()
		if len(sa) != oldView.Size() {
			sa = make([]uint32, oldView.Size())
		}
		sais.MakeSuffixArraySourceIntoWithWorkspace(oldView.SuffixSource(), oldView.Cardinality(), sa, &saWorkspace)

		eqMap.BuildWithEncodedViews(sa, oldView, newView, affinities, MinEquivalenceSimilarity)
	}

	return eqMap
}
