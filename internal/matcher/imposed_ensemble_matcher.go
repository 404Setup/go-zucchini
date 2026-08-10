package matcher

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/404Setup/go-zucchini/internal/types"
)

type ImposedEnsembleMatcher struct {
	imposedMatches string
	matches        []types.ElementMatch
	numIdentical   int
}

func NewImposedEnsembleMatcher(imposedMatches string) *ImposedEnsembleMatcher {
	return &ImposedEnsembleMatcher{imposedMatches: imposedMatches}
}

func (m *ImposedEnsembleMatcher) Matches() []types.ElementMatch {
	return m.matches
}

func (m *ImposedEnsembleMatcher) NumIdentical() int {
	return m.numIdentical
}

func (m *ImposedEnsembleMatcher) RunMatch(oldImage, newImage []byte) bool {
	return m.runMatchWithDetector(oldImage, newImage, DetectElementFromDisassembler)
}

func (m *ImposedEnsembleMatcher) runMatchWithDetector(oldImage, newImage []byte, detector ElementDetector) bool {
	m.matches = nil
	m.numIdentical = 0
	if m.imposedMatches == "" {
		return true
	}

	for pair := range strings.SplitSeq(m.imposedMatches, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			return false
		}
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			return false
		}
		oldParts := strings.Split(parts[0], "+")
		newParts := strings.Split(parts[1], "+")
		if len(oldParts) != 2 || len(newParts) != 2 {
			return false
		}

		oldOffset, err1 := strconv.ParseUint(strings.TrimSpace(oldParts[0]), 10, 32)
		oldSize, err2 := strconv.ParseUint(strings.TrimSpace(oldParts[1]), 10, 32)
		newOffset, err3 := strconv.ParseUint(strings.TrimSpace(newParts[0]), 10, 32)
		newSize, err4 := strconv.ParseUint(strings.TrimSpace(newParts[1]), 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return false
		}

		if oldSize == 0 || newSize == 0 ||
			oldOffset+oldSize > uint64(len(oldImage)) || newOffset+newSize > uint64(len(newImage)) {
			return false
		}

		m.matches = append(m.matches, types.ElementMatch{
			OldElement: types.Element{Region: types.BufferRegion{Offset: int(oldOffset), Size: int(oldSize)}, ExeType: types.ExecutableTypeUnknown},
			NewElement: types.Element{Region: types.BufferRegion{Offset: int(newOffset), Size: int(newSize)}, ExeType: types.ExecutableTypeUnknown},
		})
	}

	sort.Slice(m.matches, func(i, j int) bool {
		return m.matches[i].NewElement.Region.Offset < m.matches[j].NewElement.Region.Offset
	})
	for i := 1; i < len(m.matches); i++ {
		if m.matches[i-1].NewElement.Region.Hi() > m.matches[i].NewElement.Region.Offset {
			m.matches = nil
			return false
		}
	}

	kept := m.matches[:0]
	for _, match := range m.matches {
		oldRegion := match.OldElement.Region
		newRegion := match.NewElement.Region
		oldSub := oldImage[oldRegion.Offset:oldRegion.Hi()]
		newSub := newImage[newRegion.Offset:newRegion.Hi()]
		if bytes.Equal(oldSub, newSub) {
			m.numIdentical++
			continue
		}
		oldDetected, okOld := detector(oldSub)
		newDetected, okNew := detector(newSub)
		if !okOld || !okNew {
			continue
		}
		if oldDetected.ExeType != newDetected.ExeType {
			m.matches = nil
			return false
		}
		match.OldElement.ExeType = oldDetected.ExeType
		match.NewElement.ExeType = newDetected.ExeType
		kept = append(kept, match)
	}
	m.matches = kept
	return true
}
