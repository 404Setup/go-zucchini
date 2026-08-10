//go:build amd64 && gc && !purego && asmcompare

package matcher

import (
	"bytes"
	"math/bits"
	"sort"
)

func ordinaryRunLength(idx *ImageIndex, start, limit int) int {
	if limit <= 0 || idx.refCover == nil {
		return max(limit, 0)
	}

	end := start + limit
	word := start >> 6
	covered := idx.refCover[word] & (^uint64(0) << uint(start&63))
	if covered != 0 {
		return min(word*64+bits.TrailingZeros64(covered)-start, limit)
	}
	for word++; word < len(idx.refCover) && word*64 < end; word++ {
		if idx.refCover[word] != 0 {
			return min(word*64+bits.TrailingZeros64(idx.refCover[word])-start, limit)
		}
	}
	return limit
}

// compareEncodedPrefix compares exactly limit projection symbols. Ordinary
// byte regions are compared in batches; reference symbols remain in Go so the
// compact projection semantics and reference boundaries stay authoritative.
func compareEncodedPrefix(oldView, newView *EncodedView, oldLo, newLo, limit int) int {
	const (
		scalarProbeLength    = 16
		maxOrdinaryRunLength = 256
	)
	for offset := 0; offset < limit; {
		probeEnd := min(offset+scalarProbeLength, limit)
		for ; offset < probeEnd; offset++ {
			oldValue := oldView.QueryAt(oldLo + offset)
			newValue := newView.QueryAt(newLo + offset)
			if oldValue < newValue {
				return -1
			}
			if oldValue > newValue {
				return 1
			}
		}
		if offset == limit {
			return 0
		}

		remaining := limit - offset
		batchLimit := min(remaining, maxOrdinaryRunLength)
		oldRun := ordinaryRunLength(oldView.imageIndex, oldLo+offset, batchLimit)
		newRun := ordinaryRunLength(newView.imageIndex, newLo+offset, batchLimit)
		run := min(oldRun, newRun)
		if run > 0 {
			oldBytes := oldView.imageIndex.image[oldLo+offset : oldLo+offset+run]
			newBytes := newView.imageIndex.image[newLo+offset : newLo+offset+run]
			if comparison := bytes.Compare(oldBytes, newBytes); comparison != 0 {
				return comparison
			}
			offset += run
		}
	}
	return 0
}

func suffixLowerBoundEncoded(sa []uint32, oldView, newView *EncodedView, queryLo int) int {
	queryLen := newView.Size() - queryLo
	return sort.Search(len(sa), func(i int) bool {
		idx := int(sa[i])
		oldSuffixLen := oldView.Size() - idx
		minLen := min(queryLen, oldSuffixLen)
		if comparison := compareEncodedPrefix(oldView, newView, idx, queryLo, minLen); comparison != 0 {
			return comparison > 0
		}
		return oldSuffixLen >= queryLen
	})
}
