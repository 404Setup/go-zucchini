package matcher

import (
	"bytes"
	"math"

	"github.com/404Setup/go-zucchini/internal/types"
)

type HeuristicEnsembleMatcher struct {
	matches      []types.ElementMatch
	numIdentical int
}

func NewHeuristicEnsembleMatcher() *HeuristicEnsembleMatcher {
	return &HeuristicEnsembleMatcher{}
}

func (m *HeuristicEnsembleMatcher) Matches() []types.ElementMatch {
	return m.matches
}

func (m *HeuristicEnsembleMatcher) NumIdentical() int {
	return m.numIdentical
}

func unsafeDifference(oldElem, newElem types.Element) bool {
	const maxBloat = 2.0
	const minWorrysomeDiff = 2 << 20

	loSize := min(newElem.Region.Size, oldElem.Region.Size)
	hiSize := max(newElem.Region.Size, oldElem.Region.Size)

	if hiSize-loSize < minWorrysomeDiff {
		return false
	}
	if float64(hiSize) < float64(loSize)*maxBloat {
		return false
	}
	return true
}

func findEmbeddedElements(image []byte, detector ElementDetector) ([]types.Element, bool) {
	const elementLimit = 256
	var elements []types.Element
	finder := NewElementFinder(image, detector)
	for {
		elem, ok := finder.GetNext()
		if !ok {
			break
		}
		elements = append(elements, elem)
		if len(elements) >= elementLimit {
			return nil, false
		}
	}
	return elements, true
}

func (m *HeuristicEnsembleMatcher) RunMatch(oldImage, newImage []byte) bool {
	m.matches = nil
	m.numIdentical = 0

	oldElements, ok := findEmbeddedElements(oldImage, DetectElementFromDisassembler)
	if !ok {
		return false
	}
	newElements, ok := findEmbeddedElements(newImage, DetectElementFromDisassembler)
	if !ok {
		return false
	}

	if len(oldElements) == 0 || len(newElements) == 0 {
		return true
	}

	oldHis := make([]*BinaryDataHistogram, len(oldElements))
	for i, elem := range oldElements {
		h := NewBinaryDataHistogram()
		if elem.Region.Hi() <= len(oldImage) {
			h.Compute(oldImage[elem.Region.Offset:elem.Region.Hi()])
		}
		oldHis[i] = h
	}

	type matchResult struct {
		oldIdx int
		newIdx int
		dist   float64
	}
	var results []matchResult

	newHis := NewBinaryDataHistogram()
	for inew, newElem := range newElements {
		if newElem.Region.Hi() <= len(newImage) {
			newHis.Compute(newImage[newElem.Region.Offset:newElem.Region.Hi()])
		}

		bestDist := math.MaxFloat64
		bestOldIdx := -1
		isIdentical := false

		for iold, oldElem := range oldElements {
			if oldElem.ExeType != newElem.ExeType {
				continue
			}
			if unsafeDifference(oldElem, newElem) {
				continue
			}
			dist := oldHis[iold].Distance(newHis)
			if bestDist > dist {
				bestOldIdx = iold
				bestDist = dist
				if bestDist == 0 {
					subOld := oldImage[oldElem.Region.Offset:oldElem.Region.Hi()]
					subNew := newImage[newElem.Region.Offset:newElem.Region.Hi()]
					if bytes.Equal(subOld, subNew) {
						isIdentical = true
						break
					}
				}
			}
		}

		if bestOldIdx != -1 {
			if isIdentical {
				m.numIdentical++
			} else {
				results = append(results, matchResult{oldIdx: bestOldIdx, newIdx: inew, dist: bestDist})
			}
		}
	}

	if len(results) > 0 {
		detector := NewOutlierDetector()
		for _, res := range results {
			if res.dist > 0 {
				detector.Add(res.dist)
			}
		}
		detector.Prepare()

		for _, res := range results {
			if detector.DecideOutlier(res.dist) <= 0 {
				m.matches = append(m.matches, types.ElementMatch{
					OldElement: oldElements[res.oldIdx],
					NewElement: newElements[res.newIdx],
				})
			}
		}
	}

	return true
}
