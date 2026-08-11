package zucchini

import (
	"testing"

	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/matcher"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/types"
)

// TestGenVsApplyTargetPools reconstructs the target pool independently through
// the generation and application algorithms and verifies their shared invariant.
func TestGenVsApplyTargetPools(t *testing.T) {
	oldImage := makeSyntheticPE64(0)
	newImage := makeSyntheticPE64(0x5A)

	exeType := types.ExecutableTypeWin32X64

	oldDisasm := matcher.MakeDisassemblerOfType(oldImage, exeType)
	newDisasm := matcher.MakeDisassemblerOfType(newImage, exeType)
	if oldDisasm == nil || newDisasm == nil {
		t.Fatal("failed to create disassemblers")
	}

	oldIdx := matcher.NewImageIndex(oldImage)
	newIdx := matcher.NewImageIndex(newImage)
	if !oldIdx.Initialize(oldDisasm) || !newIdx.Initialize(newDisasm) {
		t.Fatal("failed to initialize image indexes")
	}

	eqMap := matcher.CreateEquivalenceMap(oldIdx, newIdx, oldDisasm.NumEquivalenceIterations())

	var eqs []types.Equivalence
	for _, c := range eqMap.Candidates() {
		eqs = append(eqs, c.Eq)
	}
	offsetMapper := matcher.NewOffsetMapper(eqs, types.Offset(len(oldImage)), types.Offset(len(newImage)))

	// --- Gen-side pool construction (mirrors GenerateExecutableElement) ---
	genPools := make(map[types.PoolTag][]types.Offset)
	genExtra := make(map[types.PoolTag][]types.Offset)
	for poolTag, oldPool := range oldIdx.TargetPools() {
		srcTargets := make([]types.Offset, len(oldPool.Targets()))
		copy(srcTargets, oldPool.Targets())
		projOld := matcher.NewTargetPoolWithTargets(srcTargets)
		projOld.FilterAndProject(*offsetMapper)

		newPool := newIdx.Pool(poolTag)
		var extraTargets []types.Offset
		if newPool != nil {
			for _, tg := range newPool.Targets() {
				if projOld.KeyForOffset(tg) == uint32(projOld.Size()) {
					extraTargets = append(extraTargets, tg)
				}
			}
		}
		projOld.InsertTargets(extraTargets)

		out := make([]types.Offset, len(projOld.Targets()))
		copy(out, projOld.Targets())
		genPools[poolTag] = out
		genExtra[poolTag] = extraTargets
	}

	// --- Apply-side pool construction (mirrors ApplyReferencesCorrection) ---
	oldGroups := oldDisasm.MakeReferenceGroups()
	poolGroups := make(map[types.PoolTag][]disasm.ReferenceGroup)
	for _, g := range oldGroups {
		poolGroups[g.PoolTag()] = append(poolGroups[g.PoolTag()], g)
	}

	applyPools := make(map[types.PoolTag][]types.Offset)
	for poolTag, subGroups := range poolGroups {
		targetPool := matcher.NewTargetPool()
		var all []types.Offset
		for _, g := range subGroups {
			reader := g.GetReader(0, types.Offset(len(oldImage)))
			for {
				ref, ok := reader.GetNext()
				if !ok {
					break
				}
				all = append(all, ref.Target)
			}
		}
		targetPool.InsertTargets(all)
		targetPool.FilterAndProject(*offsetMapper)
		targetPool.InsertTargets(genExtra[poolTag])

		out := make([]types.Offset, len(targetPool.Targets()))
		copy(out, targetPool.Targets())
		applyPools[poolTag] = out
	}

	for poolTag, genT := range genPools {
		applyT, ok := applyPools[poolTag]
		if !ok {
			t.Errorf("pool %d: present in gen, absent in apply", poolTag)
			continue
		}
		if len(genT) != len(applyT) {
			t.Errorf("pool %d: SIZE MISMATCH gen=%d apply=%d (extra=%d)",
				poolTag, len(genT), len(applyT), len(genExtra[poolTag]))
			continue
		}
		diffs := 0
		firstDiff := -1
		for i := range genT {
			if genT[i] != applyT[i] {
				diffs++
				if firstDiff < 0 {
					firstDiff = i
				}
			}
		}
		if diffs != 0 {
			t.Errorf("pool %d: %d differing entries, first at %d (gen=%d apply=%d)",
				poolTag, diffs, firstDiff, genT[firstDiff], applyT[firstDiff])
		} else {
			t.Logf("pool %d: MATCH (%d targets, %d extra)", poolTag, len(genT), len(genExtra[poolTag]))
		}
	}
}

// TestRefDeltaCountGenVsApply compares how many reference-deltas generation
// writes against how many the apply path attempts to consume. A mismatch means
// the two sides disagree on which references are covered by equivalences, which
// desynchronizes the whole stream.
func TestRefDeltaCountGenVsApply(t *testing.T) {
	oldImage := makeSyntheticPE64(0)
	newImage := makeSyntheticPE64(0x5A)

	exeType := types.ExecutableTypeWin32X64
	oldDisasm := matcher.MakeDisassemblerOfType(oldImage, exeType)
	newDisasm := matcher.MakeDisassemblerOfType(newImage, exeType)
	oldIdx := matcher.NewImageIndex(oldImage)
	newIdx := matcher.NewImageIndex(newImage)
	if !oldIdx.Initialize(oldDisasm) || !newIdx.Initialize(newDisasm) {
		t.Fatal("init failed")
	}
	eqMap := matcher.CreateEquivalenceMap(oldIdx, newIdx, oldDisasm.NumEquivalenceIterations())

	var eqs []types.Equivalence
	for _, c := range eqMap.Candidates() {
		eqs = append(eqs, c.Eq)
	}

	// Gen side: count deltas emitted, per type.
	genCounts := make(map[types.TypeTag]int)
	for poolTag, oldPool := range oldIdx.TargetPools() {
		_ = poolTag
		for _, typeTag := range oldPool.Types() {
			srcRefs := oldIdx.Refs(typeTag)
			dstRefs := newIdx.Refs(typeTag)
			if srcRefs == nil || dstRefs == nil {
				continue
			}
			refWidth := srcRefs.Width()
			dstReferences := dstRefs.References()
			dstIdx := 0
			count := 0
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
				for dstIdx < len(dstReferences) && dstReferences[dstIdx].Location+refWidth <= eq.DstEnd() {
					count++
					dstIdx++
				}
				if dstIdx == len(dstReferences) {
					break
				}
			}
			genCounts[typeTag] = count
		}
	}

	// Apply side: count deltas consumed, per type.
	oldGroups := oldDisasm.MakeReferenceGroups()
	applyCounts := make(map[types.TypeTag]int)
	for _, g := range oldGroups {
		count := 0
		for _, eq := range eqs {
			refGen := g.GetReader(eq.SrcOffset, eq.SrcEnd())
			for {
				_, ok := refGen.GetNext()
				if !ok {
					break
				}
				count++
			}
		}
		applyCounts[g.TypeTag()] = count
	}

	totalGen, totalApply := 0, 0
	for typeTag, gc := range genCounts {
		ac := applyCounts[typeTag]
		totalGen += gc
		totalApply += ac
		if gc != ac {
			t.Errorf("type %d: DELTA COUNT MISMATCH gen wrote %d, apply consumes %d (diff %d)",
				typeTag, gc, ac, ac-gc)
		} else {
			t.Logf("type %d: count MATCH (%d)", typeTag, gc)
		}
	}
	t.Logf("total: gen=%d apply=%d", totalGen, totalApply)

	// Cross-check against the actual patch stream length.
	patchBytes, err := GenerateBuffer(oldImage, newImage)
	if err != nil {
		t.Fatalf("GenerateBuffer: %v", err)
	}
	reader, ok := patch.CreateEnsemblePatchReader(patchBytes)
	if !ok {
		t.Fatal("failed to parse generated patch")
	}
	for _, elem := range reader.Elements() {
		e := elem
		src := e.GetReferenceDeltaSource()
		n := 0
		for {
			_, ok := src.GetNext()
			if !ok {
				break
			}
			n++
		}
		t.Logf("patch refdelta entries: %d (gen counted %d)", n, totalGen)
	}
}
