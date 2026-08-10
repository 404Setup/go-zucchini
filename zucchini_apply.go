package zucchini

import (
	"slices"

	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/matcher"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/types"
)

func ApplyEquivalenceAndExtraData(
	oldImage []byte,
	patchReader *patch.PatchElementReader,
	newImage []byte,
) bool {
	equivSource := patchReader.GetEquivalenceSource()
	extraSource := patchReader.GetExtraDataSource()
	dstIt := 0

	for {
		eq, ok := equivSource.GetNext()
		if !ok {
			break
		}
		nextDstIt := int(eq.DstOffset)
		copyLength := int(eq.Length)
		srcOffset := int(eq.SrcOffset)
		if nextDstIt < dstIt || nextDstIt > len(newImage) ||
			copyLength > len(newImage)-nextDstIt ||
			srcOffset > len(oldImage) || copyLength > len(oldImage)-srcOffset {
			return false
		}
		gap := types.Offset(nextDstIt - dstIt)
		extraData, okExtra := extraSource.GetNext(gap)
		if !okExtra {
			return false
		}
		copy(newImage[dstIt:nextDstIt], extraData)
		dstIt = nextDstIt

		copy(newImage[dstIt:dstIt+copyLength], oldImage[srcOffset:srcOffset+copyLength])
		dstIt += copyLength
	}

	if dstIt > len(newImage) {
		return false
	}
	gap := types.Offset(len(newImage) - dstIt)
	extraData, okExtra := extraSource.GetNext(gap)
	if !okExtra {
		return false
	}
	copy(newImage[dstIt:], extraData)
	return equivSource.Done() && extraSource.Done()
}

func ApplyRawDelta(
	patchReader *patch.PatchElementReader,
	newImage []byte,
) bool {
	equivSource := patchReader.GetEquivalenceSource()
	rawDeltaSource := patchReader.GetRawDeltaSource()

	eq, hasEq := equivSource.GetNext()
	var baseCopyOffset types.Offset = 0

	for {
		delta, ok := rawDeltaSource.GetNext()
		if !ok {
			break
		}
		for hasEq && baseCopyOffset+eq.Length <= delta.CopyOffset {
			baseCopyOffset += eq.Length
			eq, hasEq = equivSource.GetNext()
		}
		if !hasEq {
			return false
		}
		if delta.CopyOffset < baseCopyOffset || delta.CopyOffset >= baseCopyOffset+eq.Length {
			return false
		}

		dstIdx := int(eq.DstOffset - baseCopyOffset + delta.CopyOffset)
		if dstIdx < 0 || dstIdx >= len(newImage) {
			return false
		}
		newImage[dstIdx] = byte(int(newImage[dstIdx]) + int(delta.Diff))
	}

	return rawDeltaSource.Done()
}

func ApplyReferencesCorrection(
	exeType types.ExecutableType,
	oldImage []byte,
	patchReader *patch.PatchElementReader,
	newImage []byte,
) bool {
	if exeType == types.ExecutableTypeNoOp {
		return patchReader.GetReferenceDeltaSource().Done()
	}

	oldDisasm := matcher.MakeDisassemblerOfType(oldImage, exeType)
	newDisasm := matcher.MakeDisassemblerOfType(newImage, exeType)
	if oldDisasm == nil || newDisasm == nil {
		return false
	}
	if oldDisasm.Size() != len(oldImage) || newDisasm.Size() != len(newImage) {
		return false
	}

	refDeltaSource := patchReader.GetReferenceDeltaSource()

	oldGroups := oldDisasm.MakeReferenceGroups()
	newGroups := disasm.MakeReferenceGroupsForWriter(newDisasm)

	poolGroups := make(map[types.PoolTag][]disasm.ReferenceGroup)
	for _, g := range oldGroups {
		poolGroups[g.PoolTag()] = append(poolGroups[g.PoolTag()], g)
	}

	var equivList []types.Equivalence
	eqSrc := patchReader.GetEquivalenceSource()
	for {
		eq, ok := eqSrc.GetNext()
		if !ok {
			break
		}
		equivList = append(equivList, eq)
	}

	// OffsetMapper sorts and prunes by source. Keep equivList in patch
	// (destination) order because reference deltas are serialized in that order.
	offsetMapper := matcher.NewOffsetMapper(equivList, types.Offset(len(oldImage)), types.Offset(len(newImage)))

	var poolTags []types.PoolTag
	for tag := range poolGroups {
		poolTags = append(poolTags, tag)
	}
	slices.Sort(poolTags)

	for _, poolTag := range poolTags {
		subGroups := poolGroups[poolTag]
		targetCount := 0
		for _, g := range subGroups {
			targetCount += g.ReferenceCountHint
		}
		oldTargets := make([]types.Offset, 0, targetCount)
		for _, g := range subGroups {
			reader := g.GetReader(0, types.Offset(len(oldImage)))
			for {
				ref, ok := reader.GetNext()
				if !ok {
					break
				}
				oldTargets = append(oldTargets, ref.Target)
			}
		}
		targetPool := matcher.NewTargetPoolFromOwnedTargets(oldTargets)
		targetPool.FilterAndProject(*offsetMapper)

		extraTargetSource := patchReader.GetExtraTargetSource(poolTag)
		var extra []types.Offset
		for {
			t, ok := extraTargetSource.GetNext()
			if !ok {
				break
			}
			extra = append(extra, t)
		}
		if !extraTargetSource.Done() {
			return false
		}
		targetPool.InsertTargets(extra)

		for _, group := range subGroups {
			typeTag := group.TypeTag()
			var writer types.ReferenceWriter
			for _, ng := range newGroups {
				if ng.TypeTag() == typeTag {
					writer = ng.GetWriter(newImage)
					break
				}
			}
			if writer == nil {
				continue
			}

			for _, eq := range equivList {
				refGen := group.GetReader(eq.SrcOffset, eq.SrcEnd())
				for {
					ref, ok := refGen.GetNext()
					if !ok {
						break
					}
					projectedTarget := offsetMapper.ExtendedForwardProject(ref.Target)
					expectedKey := targetPool.KeyForNearestOffset(projectedTarget)

					delta, okDelta := refDeltaSource.GetNext()
					if !okDelta {
						return false
					}
					key := int64(expectedKey) + int64(delta)
					if key < 0 || !targetPool.KeyIsValid(uint32(key)) {
						return false
					}
					ref.Target = targetPool.OffsetForKey(uint32(key))
					ref.Location = ref.Location - eq.SrcOffset + eq.DstOffset
					writer.PutNext(ref)
				}
			}
		}
	}

	return refDeltaSource.Done()
}

func ApplyElement(
	exeType types.ExecutableType,
	oldImage []byte,
	patchReader *patch.PatchElementReader,
	newImage []byte,
) bool {
	if !ApplyEquivalenceAndExtraData(oldImage, patchReader, newImage) {
		return false
	}
	if !ApplyRawDelta(patchReader, newImage) {
		return false
	}
	if !ApplyReferencesCorrection(exeType, oldImage, patchReader, newImage) {
		return false
	}
	return true
}

func ApplyBuffer(
	oldImage []byte,
	patchReader *patch.EnsemblePatchReader,
	newImage []byte,
) StatusCode {
	if !patchReader.CheckOldFile(oldImage) {
		return StatusInvalidOldImage
	}
	if len(newImage) != int(patchReader.Header().NewSize) {
		return StatusInvalidNewImage
	}
	return applyBufferWithCheckedOldImage(oldImage, patchReader, newImage)
}

func applyBufferWithCheckedOldImage(
	oldImage []byte,
	patchReader *patch.EnsemblePatchReader,
	newImage []byte,
) StatusCode {
	for _, elemPatch := range patchReader.Elements() {
		match := elemPatch.ElementMatch()
		oldSub := oldImage[match.OldElement.Region.Offset:match.OldElement.Region.Hi()]
		newSub := newImage[match.NewElement.Region.Offset:match.NewElement.Region.Hi()]
		elemReader := elemPatch
		if !ApplyElement(match.OldElement.ExeType, oldSub, &elemReader, newSub) {
			return StatusFatal
		}
	}

	if !patchReader.CheckNewFile(newImage) {
		return StatusInvalidNewImage
	}
	return StatusSuccess
}

func Apply(oldImage, patchBytes []byte) ([]byte, error) {
	reader, ok := patch.CreateEnsemblePatchReader(patchBytes)
	if !ok {
		return nil, NewError(StatusInvalidPatch, "Failed to parse ensemble patch")
	}

	if !reader.CheckOldFile(oldImage) {
		return nil, NewError(StatusInvalidOldImage, "Old image does not match patch")
	}
	newSize := uint64(reader.Header().NewSize)
	if newSize > uint64(maxIntValue()) {
		return nil, NewError(StatusInvalidNewImage, "New image is too large for this platform")
	}
	newImage := make([]byte, int(newSize))
	if code := applyBufferWithCheckedOldImage(oldImage, reader, newImage); code != StatusSuccess {
		return nil, NewError(code, "ApplyBuffer failed")
	}
	return newImage, nil
}

// ApplyTo applies patchBytes into a caller-provided output buffer. The buffer
// length must equal the new image size stored in the patch. This is useful for
// pooled buffers and memory-mapped files because it avoids allocating the full
// output image on the Go heap.
func ApplyTo(oldImage, patchBytes, newImage []byte) error {
	reader, ok := patch.CreateEnsemblePatchReader(patchBytes)
	if !ok {
		return NewError(StatusInvalidPatch, "Failed to parse ensemble patch")
	}
	if len(newImage) != int(reader.Header().NewSize) {
		return NewError(StatusInvalidNewImage, "Output buffer has the wrong size")
	}
	return applyWithReader(oldImage, reader, newImage)
}

func applyWithReader(oldImage []byte, reader *patch.EnsemblePatchReader, newImage []byte) error {
	code := ApplyBuffer(oldImage, reader, newImage)
	if code != StatusSuccess {
		return NewError(code, "ApplyBuffer failed")
	}
	return nil
}
