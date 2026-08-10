package zucchini

import (
	"slices"
	"sort"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/matcher"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/sais"
	"github.com/404Setup/go-zucchini/internal/types"
)

const (
	MinEquivalenceSimilarity = 12.0
	MinLabelAffinity         = 64.0
)

func GenerateEquivalencesAndExtraData(
	newImage []byte,
	eqMap *matcher.EquivalenceMap,
	patchWriter *patch.PatchElementWriter,
) bool {
	eqSink := patch.NewEquivalenceSink()
	for _, cand := range eqMap.Candidates() {
		eqSink.PutNext(cand.Eq)
	}
	patchWriter.SetEquivalenceSink(eqSink)

	extraSink := patch.NewExtraDataSink(newImage)
	var dstOffset types.Offset = 0
	for _, cand := range eqMap.Candidates() {
		if !extraSink.PutRegion(int(dstOffset), int(cand.Eq.DstOffset-dstOffset)) {
			return false
		}
		dstOffset = cand.Eq.DstEnd()
	}
	if !extraSink.PutRegion(int(dstOffset), len(newImage)-int(dstOffset)) {
		return false
	}
	patchWriter.SetExtraDataSink(extraSink)

	return true
}

func GenerateRawDelta(
	oldImage []byte,
	newImage []byte,
	eqMap *matcher.EquivalenceMap,
	newImageIdx *matcher.ImageIndex,
	referenceMixers map[types.TypeTag]disasm.ReferenceMixer,
	patchWriter *patch.PatchElementWriter,
) bool {
	rawSink := patch.NewRawDeltaSink()
	var baseCopyOffset types.Offset = 0

	for _, cand := range eqMap.Candidates() {
		eq := cand.Eq
		for i := types.Offset(0); i < eq.Length; {
			dstPos := eq.DstOffset + i
			srcPos := eq.SrcOffset + i
			if newImageIdx.IsReference(dstPos) {
				typeTag := newImageIdx.LookupType(dstPos)
				refSet := newImageIdx.Refs(typeTag)
				width := refSet.Width()
				if referenceMixers != nil {
					if mixer := referenceMixers[typeTag]; mixer != nil {
						mixed := mixer.Mix(srcPos, dstPos)
						for j := types.Offset(0); j < width; j++ {
							diff := int8(mixed[j]) - int8(oldImage[srcPos+j])
							if diff != 0 {
								rawSink.PutNext(patch.RawDeltaUnit{CopyOffset: baseCopyOffset + i + j, Diff: diff})
							}
						}
					}
				}
				i += width
			} else {
				diff := int8(newImage[dstPos]) - int8(oldImage[srcPos])
				if diff != 0 {
					rawSink.PutNext(patch.RawDeltaUnit{
						CopyOffset: baseCopyOffset + i,
						Diff:       diff,
					})
				}
				i++
			}
		}
		baseCopyOffset += eq.Length
	}

	patchWriter.SetRawDeltaSink(rawSink)
	return true
}

func GenerateReferencesDelta(
	srcRefs *matcher.ReferenceSet,
	dstRefs *matcher.ReferenceSet,
	projectedTargetPool *matcher.TargetPool,
	offsetMapper *matcher.OffsetMapper,
	eqMap *matcher.EquivalenceMap,
	refDeltaSink *patch.ReferenceDeltaSink,
) bool {
	refWidth := srcRefs.Width()
	dstReferences := dstRefs.References()
	srcReferences := srcRefs.References()

	dstIdx := 0

	for _, cand := range eqMap.Candidates() {
		eq := cand.Eq
		for dstIdx < len(dstReferences) && dstReferences[dstIdx].Location < eq.DstOffset {
			dstIdx++
		}
		if dstIdx == len(dstReferences) {
			break
		}
		if dstReferences[dstIdx].Location >= eq.DstEnd() {
			continue
		}

		srcLoc := eq.SrcOffset + (dstReferences[dstIdx].Location - eq.DstOffset)
		srcIdx := sort.Search(len(srcReferences), func(i int) bool {
			return srcReferences[i].Location >= srcLoc
		})

		for dstIdx < len(dstReferences) && dstReferences[dstIdx].Location+refWidth <= eq.DstEnd() {
			if srcIdx >= len(srcReferences) {
				break
			}
			oldOffset := srcReferences[srcIdx].Target
			newEstOffset := offsetMapper.ExtendedForwardProject(oldOffset)
			newEstKey := projectedTargetPool.KeyForNearestOffset(newEstOffset)

			newOffset := dstReferences[dstIdx].Target
			newKey := projectedTargetPool.KeyForOffset(newOffset)

			refDeltaSink.PutNext(int32(newKey - newEstKey))

			dstIdx++
			srcIdx++
		}

		if dstIdx == len(dstReferences) {
			break
		}
	}

	return true
}

func GenerateExecutableElement(
	exeType types.ExecutableType,
	oldImage []byte,
	newImage []byte,
	patchWriter *patch.PatchElementWriter,
) bool {
	oldDisasm := matcher.MakeDisassemblerOfType(oldImage, exeType)
	newDisasm := matcher.MakeDisassemblerOfType(newImage, exeType)
	if oldDisasm == nil || newDisasm == nil {
		return false
	}

	oldIdx := matcher.NewImageIndex(oldImage)
	newIdx := matcher.NewImageIndex(newImage)
	if !oldIdx.Initialize(oldDisasm) || !newIdx.Initialize(newDisasm) {
		return false
	}

	iterations := oldDisasm.NumEquivalenceIterations()
	var referenceMixers map[types.TypeTag]disasm.ReferenceMixer
	for _, group := range oldDisasm.MakeReferenceGroups() {
		if mixer := group.GetMixer(oldImage, newImage); mixer != nil {
			if referenceMixers == nil {
				referenceMixers = make(map[types.TypeTag]disasm.ReferenceMixer)
			}
			referenceMixers[group.TypeTag()] = mixer
		}
	}
	oldDisasm = nil
	newDisasm = nil

	eqMap := matcher.CreateEquivalenceMap(oldIdx, newIdx, iterations)

	offsetMapper := matcher.NewOffsetMapperFromOwnedEquivalences(extractEquivalences(eqMap), types.Offset(len(oldImage)), types.Offset(len(newImage)))

	refDeltaSink := patch.NewReferenceDeltaSink()

	var poolTags []types.PoolTag
	for tag := range oldIdx.TargetPools() {
		poolTags = append(poolTags, tag)
	}
	slices.Sort(poolTags)

	for _, poolTag := range poolTags {
		oldPool := oldIdx.TargetPools()[poolTag]
		projOldTargets := matcher.NewTargetPoolWithTargets(oldPool.Targets())
		projOldTargets.FilterAndProject(*offsetMapper)

		newPool := newIdx.Pool(poolTag)
		var extraTargets []types.Offset
		if newPool != nil {
			for _, t := range newPool.Targets() {
				if projOldTargets.KeyForOffset(t) == uint32(projOldTargets.Size()) {
					extraTargets = append(extraTargets, t)
				}
			}
		}

		targetSink := patch.NewTargetSink()
		for _, t := range extraTargets {
			targetSink.PutNext(t)
		}
		patchWriter.SetTargetSink(poolTag, targetSink)

		projOldTargets.InsertTargets(extraTargets)

		for _, typeTag := range oldPool.Types() {
			srcRefs := oldIdx.Refs(typeTag)
			dstRefs := newIdx.Refs(typeTag)
			if srcRefs != nil && dstRefs != nil {
				GenerateReferencesDelta(srcRefs, dstRefs, projOldTargets, offsetMapper, eqMap, refDeltaSink)
			}
		}
	}

	patchWriter.SetReferenceDeltaSink(refDeltaSink)
	return GenerateEquivalencesAndExtraData(newImage, eqMap, patchWriter) &&
		GenerateRawDelta(oldImage, newImage, eqMap, newIdx, referenceMixers, patchWriter)
}

func extractEquivalences(eqMap *matcher.EquivalenceMap) []types.Equivalence {
	var eqs []types.Equivalence
	for _, c := range eqMap.Candidates() {
		eqs = append(eqs, c.Eq)
	}
	return eqs
}

func GenerateRawElement(
	oldSA []uint32,
	oldProj []uint32,
	oldImage []byte,
	newImage []byte,
	patchWriter *patch.PatchElementWriter,
) bool {
	oldIdx := matcher.NewImageIndex(oldImage)
	newIdx := matcher.NewImageIndex(newImage)
	oldView := matcher.NewEncodedView(oldIdx)
	newView := matcher.NewEncodedView(newIdx)
	eqMap := matcher.NewEquivalenceMap()
	eqMap.BuildWithProjections(oldSA, oldProj, oldView, newView, nil, MinEquivalenceSimilarity)

	patchWriter.SetReferenceDeltaSink(patch.NewReferenceDeltaSink())
	return GenerateEquivalencesAndExtraData(newImage, eqMap, patchWriter) &&
		GenerateRawDelta(oldImage, newImage, eqMap, newIdx, nil, patchWriter)
}

func generateRawElementWithView(
	oldSA []uint32,
	oldView *matcher.EncodedView,
	oldImage []byte,
	newImage []byte,
	patchWriter *patch.PatchElementWriter,
) bool {
	newIdx := matcher.NewImageIndex(newImage)
	newView := matcher.NewEncodedView(newIdx)

	eqMap := matcher.NewEquivalenceMap()
	eqMap.BuildWithEncodedViews(oldSA, oldView, newView, nil, MinEquivalenceSimilarity)

	patchWriter.SetReferenceDeltaSink(patch.NewReferenceDeltaSink())
	return GenerateEquivalencesAndExtraData(newImage, eqMap, patchWriter) &&
		GenerateRawDelta(oldImage, newImage, eqMap, newIdx, nil, patchWriter)
}

func imageSizesFitPatchFormat(oldSize, newSize uint64) bool {
	limit := uint64(types.OffsetBound)
	return oldSize < limit && newSize < limit
}

func GenerateBufferRaw(oldImage, newImage []byte, patchWriter *patch.EnsemblePatchWriter) StatusCode {
	if !imageSizesFitPatchFormat(uint64(len(oldImage)), uint64(len(newImage))) {
		return StatusInvalidParam
	}
	oldIdx := matcher.NewImageIndex(oldImage)
	oldView := matcher.NewEncodedView(oldIdx)
	oldView.BuildProjectionCache()
	oldSA := sais.MakeSuffixArraySourceInto(oldView, oldView.Cardinality(), nil)

	match := types.ElementMatch{
		OldElement: types.Element{Region: types.BufferRegion{Offset: 0, Size: len(oldImage)}, ExeType: types.ExecutableTypeNoOp},
		NewElement: types.Element{Region: types.BufferRegion{Offset: 0, Size: len(newImage)}, ExeType: types.ExecutableTypeNoOp},
	}
	patchElem := patch.NewPatchElementWriter(match)
	if !generateRawElementWithView(oldSA, oldView, oldImage, newImage, patchElem) {
		return StatusFatal
	}
	patchWriter.AddElement(*patchElem)
	return StatusSuccess
}

type EnsembleMatcher interface {
	RunMatch(oldImage, newImage []byte) bool
	Matches() []types.ElementMatch
	NumIdentical() int
}

func GenerateBufferCommon(oldImage, newImage []byte, ensembleMatcher EnsembleMatcher, patchWriter *patch.EnsemblePatchWriter) StatusCode {
	if !imageSizesFitPatchFormat(uint64(len(oldImage)), uint64(len(newImage))) {
		return StatusInvalidParam
	}
	if !ensembleMatcher.RunMatch(oldImage, newImage) {
		return GenerateBufferRaw(oldImage, newImage, patchWriter)
	}

	matches := ensembleMatcher.Matches()
	if len(matches) == 0 {
		return GenerateBufferRaw(oldImage, newImage, patchWriter)
	}

	patchElementMap := make(map[types.Offset]*patch.PatchElementWriter)
	var coveredNewRegions []types.BufferRegion
	coveredNewBytes := 0

	for _, match := range matches {
		oldSub := oldImage[match.OldElement.Region.Offset:match.OldElement.Region.Hi()]
		newSub := newImage[match.NewElement.Region.Offset:match.NewElement.Region.Hi()]
		patchElem := patch.NewPatchElementWriter(match)
		if GenerateExecutableElement(match.OldElement.ExeType, oldSub, newSub, patchElem) {
			coveredNewRegions = append(coveredNewRegions, match.NewElement.Region)
			coveredNewBytes += match.NewElement.Region.Size
			patchElementMap[types.Offset(match.NewElement.Region.Offset)] = patchElem
		}
	}

	if coveredNewBytes < len(newImage) {
		entireOldElement := types.Element{Region: types.BufferRegion{Offset: 0, Size: len(oldImage)}, ExeType: types.ExecutableTypeNoOp}
		oldIdx := matcher.NewImageIndex(oldImage)
		oldView := matcher.NewEncodedView(oldIdx)
		oldView.BuildProjectionCache()
		oldSA := sais.MakeSuffixArraySourceInto(oldView, oldView.Cardinality(), nil)

		var gapLo types.Offset = 0
		coveredNewRegions = append(coveredNewRegions, types.BufferRegion{Offset: len(newImage), Size: 0})

		for _, covered := range coveredNewRegions {
			gapHi := types.Offset(covered.Offset)
			gapSize := gapHi - gapLo
			if gapSize > 0 {
				gapMatch := types.ElementMatch{
					OldElement: entireOldElement,
					NewElement: types.Element{Region: types.BufferRegion{Offset: int(gapLo), Size: int(gapSize)}, ExeType: types.ExecutableTypeNoOp},
				}
				patchElem := patch.NewPatchElementWriter(gapMatch)
				newSubImage := newImage[gapLo:gapHi]
				if !generateRawElementWithView(oldSA, oldView, oldImage, newSubImage, patchElem) {
					return StatusFatal
				}
				patchElementMap[gapLo] = patchElem
			}
			gapLo = types.Offset(covered.Hi())
		}
	}

	var offsets []types.Offset
	for off := range patchElementMap {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)

	for _, off := range offsets {
		patchWriter.AddElement(*patchElementMap[off])
	}

	return StatusSuccess
}

func GenerateBuffer(oldImage, newImage []byte) ([]byte, error) {
	patchWriter, err := generatePatchWriter(oldImage, newImage)
	if err != nil {
		return nil, err
	}

	size := patchWriter.SerializedSize()
	outBuf := make([]byte, size)
	sink := buffer.NewBufferSink(outBuf)
	if !patchWriter.SerializeInto(sink) {
		return nil, NewError(StatusFatal, "Failed to serialize patch")
	}

	return outBuf, nil
}

func generatePatchWriter(oldImage, newImage []byte) (*patch.EnsemblePatchWriter, error) {
	if !imageSizesFitPatchFormat(uint64(len(oldImage)), uint64(len(newImage))) {
		return nil, NewError(StatusInvalidParam, "Input images exceed the patch format's 32-bit size limit")
	}
	patchWriter := patch.NewEnsemblePatchWriter(oldImage, newImage)

	ensembleMatcher := matcher.NewHeuristicEnsembleMatcher()
	code := GenerateBufferCommon(oldImage, newImage, ensembleMatcher, patchWriter)
	if code != StatusSuccess {
		return nil, NewError(code, "GenerateBufferCommon failed")
	}
	return patchWriter, nil
}

func GenerateBufferImposed(oldImage, newImage []byte, imposedMatches string, patchWriter *patch.EnsemblePatchWriter) StatusCode {
	if imposedMatches == "" {
		return GenerateBufferCommon(oldImage, newImage, matcher.NewHeuristicEnsembleMatcher(), patchWriter)
	}
	m := matcher.NewImposedEnsembleMatcher(imposedMatches)
	return GenerateBufferCommon(oldImage, newImage, m, patchWriter)
}
