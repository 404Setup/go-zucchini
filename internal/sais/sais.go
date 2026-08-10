package sais

import (
	"bytes"
	"math/bits"
	"sort"
)

type slType bool

const (
	sType slType = false
	lType slType = true
)

// slBits stores the S/L type of each suffix as one bit instead of one byte,
// cutting this array from n bytes to n/8. It is live for the whole duration of
// a recursion level, and every level allocates its own, so the saving compounds
// across the recursion. Reused arena memory is not zeroed, so set() writes both
// branches explicitly rather than only setting bits.
type slBits []uint64

type workspaceLevel struct {
	sl      slBits
	scratch []uint32
}

// Workspace retains SA-IS temporary storage across calls. A Workspace is not
// safe for concurrent use; callers should keep one per active suffix sort.
type Workspace struct {
	levels []workspaceLevel
}

func (w *Workspace) level(depth int) *workspaceLevel {
	for len(w.levels) <= depth {
		w.levels = append(w.levels, workspaceLevel{})
	}
	return &w.levels[depth]
}

func (w *Workspace) slBits(depth, n int) slBits {
	level := w.level(depth)
	words := (n + 63) / 64
	if cap(level.sl) < words {
		level.sl = make(slBits, words)
	} else {
		level.sl = level.sl[:words]
		if words > 0 {
			level.sl[words-1] = 0
		}
	}
	return level.sl
}

func (w *Workspace) uint32Scratch(depth, n int) []uint32 {
	level := w.level(depth)
	if cap(level.scratch) < n {
		level.scratch = make([]uint32, n)
	} else {
		level.scratch = level.scratch[:n]
	}
	return level.scratch
}

func newSLBits(n int) slBits {
	return make(slBits, (n+63)/64)
}

func (s slBits) set(i int, v slType) {
	if v == lType {
		s[i>>6] |= 1 << uint(i&63)
	} else {
		s[i>>6] &^= 1 << uint(i&63)
	}
}

func (s slBits) get(i int) slType {
	return s[i>>6]&(1<<uint(i&63)) != 0
}

// Uint32Source is a random-access string of uint32 symbols. Keeping the
// source abstract lets callers suffix-sort compact or computed views without
// first materializing four bytes per input symbol.
type Uint32Source interface {
	Size() int
	QueryAt(i int) uint32
}

type uint32Slice []uint32

func (s uint32Slice) Size() int            { return len(s) }
func (s uint32Slice) QueryAt(i int) uint32 { return s[i] }

type byteSlice []byte

func (s byteSlice) Size() int            { return len(s) }
func (s byteSlice) QueryAt(i int) uint32 { return uint32(s[i]) }

// ProjectionSource is the compact, random-access representation used by an
// executable-aware suffix sort. Raw bytes stay in image; only references need
// the auxiliary bitsets, rank table, and projected values.
type ProjectionSource struct {
	image    []byte
	refStart []uint64
	refCover []uint64
	refRank  []uint32
	refProj  []uint32
}

func NewProjectionSource(image []byte, refStart, refCover []uint64, refRank, refProj []uint32) *ProjectionSource {
	return &ProjectionSource{
		image: image, refStart: refStart, refCover: refCover, refRank: refRank, refProj: refProj,
	}
}

func (s *ProjectionSource) Size() int { return len(s.image) }

func (s *ProjectionSource) QueryAt(i int) uint32 {
	if s.refCover == nil || s.refCover[i>>6]&(1<<uint(i&63)) == 0 {
		return uint32(s.image[i])
	}
	return s.referenceProjection(i)
}

func (s *ProjectionSource) queryOrdinary(i int) (uint32, bool) {
	if s.refCover == nil || s.refCover[i>>6]&(1<<uint(i&63)) == 0 {
		return uint32(s.image[i]), true
	}
	return 0, false
}

func (s *ProjectionSource) referenceProjection(i int) uint32 {
	if s.refStart[i>>6]&(1<<uint(i&63)) == 0 {
		return 256
	}
	word := i >> 6
	mask := (uint64(1) << uint(i&63)) - 1
	rank := int(s.refRank[word]) + bits.OnesCount64(s.refStart[word]&mask)
	return s.refProj[rank]
}

// Keep the uncommon reference branch out of the specialized induced-sort
// loops. Their ordinary-byte probes inline at each call site.
//
//go:noinline
func (s *ProjectionSource) referenceProjectionCold(i int) uint32 {
	return s.referenceProjection(i)
}

// MakeSuffixArray computes the suffix array for input byte slice str,
// where characters are in range [0, keyBound).
func MakeSuffixArray(str []byte, keyBound int) []uint32 {
	n := len(str)
	if n == 0 {
		return nil
	}
	sa := make([]uint32, n)
	if n == 1 {
		sa[0] = 0
		return sa
	}
	suffixSort(byteSlice(str), keyBound, sa, nil, nil, 0)
	return sa
}

// MakeSuffixArrayInt computes the suffix array for a slice of uint32 tokens.
func MakeSuffixArrayInt(str []uint32, keyBound int) []uint32 {
	return MakeSuffixArrayIntInto(str, keyBound, nil)
}

// MakeSuffixArrayIntInto is MakeSuffixArrayInt but writes into sa when it has
// enough capacity, avoiding a fresh len(str)*4 byte allocation. sa's contents
// are fully overwritten. Callers that reuse a buffer across calls save a
// transient peak of one whole suffix array.
func MakeSuffixArrayIntInto(str []uint32, keyBound int, sa []uint32) []uint32 {
	return MakeSuffixArraySourceInto(uint32Slice(str), keyBound, sa)
}

// MakeSuffixArraySourceInto computes the suffix array of a random-access
// source. It reuses sa when possible and never materializes the source.
func MakeSuffixArraySourceInto[S Uint32Source](str S, keyBound int, sa []uint32) []uint32 {
	return MakeSuffixArraySourceIntoWithWorkspace(str, keyBound, sa, nil)
}

// MakeSuffixArraySourceIntoWithWorkspace is MakeSuffixArraySourceInto with
// reusable temporary storage. The returned suffix array never aliases the workspace.
func MakeSuffixArraySourceIntoWithWorkspace[S Uint32Source](str S, keyBound int, sa []uint32, workspace *Workspace) []uint32 {
	n := str.Size()
	if n == 0 {
		return nil
	}
	if cap(sa) >= n {
		sa = sa[:n]
	} else {
		sa = make([]uint32, n)
	}
	if n == 1 {
		sa[0] = 0
		return sa
	}
	suffixSort(str, keyBound, sa, nil, workspace, 0)
	return sa
}

func takeUint32Scratch(scratch []uint32, n int, zero bool) ([]uint32, []uint32) {
	if len(scratch) < n {
		return make([]uint32, n), scratch
	}
	buf := scratch[:n]
	if zero {
		clear(buf)
	}
	return buf, scratch[n:]
}

func suffixSort[S Uint32Source](str S, keyBound int, sa, scratch []uint32, workspace *Workspace, depth int) {
	n := str.Size()
	if n == 1 {
		sa[0] = 0
		return
	}
	if n < 2 {
		return
	}

	var slPartition slBits
	if workspace == nil {
		slPartition = newSLBits(n)
	} else {
		slPartition = workspace.slBits(depth, n)
	}
	lmsCount := buildSLPartition(str, keyBound, slPartition, n)
	if workspace != nil {
		required := 2*keyBound + len(slPartition) + 1 + (lmsCount+31)/32
		if len(scratch) < required {
			scratch = workspace.uint32Scratch(depth, required)
		}
	}

	buckets, scratch := takeUint32Scratch(scratch, keyBound, true)
	countBuckets(str, buckets)

	bucketBounds, scratch := takeUint32Scratch(scratch, len(buckets), false)

	inducedSortUnsortedLMS(str, slPartition, buckets, bucketBounds, sa)

	if lmsCount == 0 {
		return
	}

	orderedLMS := sa[:lmsCount]
	collectSortedLmsSuffixes(slPartition, sa, orderedLMS)
	if lmsCount > 1 {
		lmsRanks, scratch := takeUint32Scratch(scratch, len(slPartition)+1, false)
		buildLmsRanks(slPartition, lmsRanks)
		lmsLabels := sa[lmsCount : 2*lmsCount]
		labelCount := labelLmsSubstrings(str, slPartition, lmsRanks, orderedLMS, lmsLabels)

		if labelCount < lmsCount {
			recSA := orderedLMS
			childScratch := sa[2*lmsCount:]
			if len(scratch) > len(childScratch) {
				childScratch = scratch
			}
			suffixSort(uint32Slice(lmsLabels), labelCount, recSA, childScratch, workspace, depth+1)

			for rank, ordinal := range recSA {
				lmsLabels[ordinal] = uint32(rank)
			}
			ordinal := 0
			previousType := sType
			for position := range n {
				currentType := slPartition.get(position)
				if currentType == sType && previousType == lType {
					recSA[lmsLabels[ordinal]] = uint32(position)
					ordinal++
				}
				previousType = currentType
			}
		}
	}

	moved, _ := takeUint32Scratch(scratch, (lmsCount+31)/32, true)
	seedOrderedLMSInPlace(str, orderedLMS, buckets, bucketBounds, moved, sa)
	induceFromSeeded(str, slPartition, buckets, bucketBounds, sa)
}

func buildSLPartition[S Uint32Source](str S, keyBound int, slPartition slBits, n int) int {
	if source, ok := any(str).(*ProjectionSource); ok {
		return buildSLPartitionProjection(source, keyBound, slPartition)
	}
	lmsCount := 0
	prevType := lType
	prevKey := uint32(keyBound)

	for i := n - 1; i >= 0; i-- {
		curKey := str.QueryAt(i)
		if curKey > prevKey || prevKey == uint32(keyBound) {
			if prevType == sType {
				lmsCount++
			}
			prevType = lType
		} else if curKey < prevKey {
			prevType = sType
		}
		slPartition.set(i, prevType)
		prevKey = curKey
	}
	return lmsCount
}

func lmsMask(slPartition slBits, word int) uint64 {
	previous := uint64(0)
	if word > 0 {
		previous = slPartition[word-1] >> 63
	}
	current := slPartition[word]
	return ^current & ((current << 1) | previous)
}

// buildLmsRanks stores the number of LMS positions in all preceding words.
// It is n/64 uint32s, much smaller than a second n/2-sized LMS array.
func buildLmsRanks(slPartition slBits, ranks []uint32) {
	ranks[0] = 0
	for i := range slPartition {
		ranks[i+1] = ranks[i] + uint32(bits.OnesCount64(lmsMask(slPartition, i)))
	}
}

func lmsRank(slPartition slBits, ranks []uint32, location int) int {
	word := location >> 6
	bit := uint(location & 63)
	before := (uint64(1) << bit) - 1
	return int(ranks[word]) + bits.OnesCount64(lmsMask(slPartition, word)&before)
}

func collectSortedLmsSuffixes(slPartition slBits, sa, lmsIndices []uint32) {
	j := 0
	for _, suffix := range sa {
		if suffix > 0 && slPartition.get(int(suffix)) == sType && slPartition.get(int(suffix)-1) == lType {
			lmsIndices[j] = suffix
			j++
		}
	}
}

func countBuckets[S Uint32Source](str S, buckets []uint32) {
	if source, ok := any(str).(*ProjectionSource); ok {
		countBucketsProjection(source, buckets)
		return
	}
	for i := 0; i < str.Size(); i++ {
		buckets[str.QueryAt(i)]++
	}
}

func inducedSortUnsortedLMS[S Uint32Source](str S, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	switch source := any(str).(type) {
	case byteSlice:
		inducedSortBytes(source, slPartition, buckets, bucketBounds, sa)
		return
	case uint32Slice:
		inducedSortUint32s(source, slPartition, buckets, bucketBounds, sa)
		return
	case *ProjectionSource:
		inducedSortProjection(source, slPartition, buckets, bucketBounds, sa)
		return
	}
	inducedSortGeneric(str, slPartition, buckets, bucketBounds, sa)
}

func inducedSortGeneric[S Uint32Source](str S, slPartition slBits, buckets []uint32, bucketBounds []uint32, sa []uint32) {
	n := uint32(str.Size())
	for i := range sa {
		sa[i] = n
	}

	if len(bucketBounds) < len(buckets) {
		bucketBounds = make([]uint32, len(buckets))
	} else {
		bucketBounds = bucketBounds[:len(buckets)]
	}

	var sum uint32
	for i, c := range buckets {
		sum += c
		bucketBounds[i] = sum
	}
	for i := int(n) - 1; i > 0; i-- {
		if slPartition.get(i) == sType && slPartition.get(i-1) == lType {
			key := str.QueryAt(i)
			bucketBounds[key]--
			sa[bucketBounds[key]] = uint32(i)
		}
	}

	bucketBounds[0] = 0
	sum = 0
	for i := 0; i < len(buckets)-1; i++ {
		sum += buckets[i]
		bucketBounds[i+1] = sum
	}

	if slPartition.get(int(n)-1) == lType {
		key := str.QueryAt(int(n - 1))
		sa[bucketBounds[key]] = n - 1
		bucketBounds[key]++
	}
	for i := range n {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == lType {
				key := str.QueryAt(int(sufIdx))
				sa[bucketBounds[key]] = sufIdx
				bucketBounds[key]++
			}
		}
	}

	sum = 0
	for i, c := range buckets {
		sum += c
		bucketBounds[i] = sum
	}
	for i := int(n) - 1; i >= 0; i-- {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == sType {
				key := str.QueryAt(int(sufIdx))
				bucketBounds[key]--
				sa[bucketBounds[key]] = sufIdx
			}
		}
	}
	if slPartition.get(int(n)-1) == sType {
		key := str.QueryAt(int(n - 1))
		bucketBounds[key]--
		sa[bucketBounds[key]] = n - 1
	}
}

func induceFromSeeded[S Uint32Source](str S, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	switch source := any(str).(type) {
	case byteSlice:
		induceSeededBytes(source, slPartition, buckets, bucketBounds, sa)
		return
	case uint32Slice:
		induceSeededUint32s(source, slPartition, buckets, bucketBounds, sa)
		return
	case *ProjectionSource:
		induceSeededProjection(source, slPartition, buckets, bucketBounds, sa)
		return
	}

	n := uint32(str.Size())
	bucketBegins(buckets, bucketBounds)
	if slPartition.get(int(n)-1) == lType {
		key := str.QueryAt(int(n - 1))
		sa[bucketBounds[key]] = n - 1
		bucketBounds[key]++
	}
	for i := range n {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == lType {
				key := str.QueryAt(int(sufIdx))
				sa[bucketBounds[key]] = sufIdx
				bucketBounds[key]++
			}
		}
	}
	bucketEnds(buckets, bucketBounds)
	for i := int(n) - 1; i >= 0; i-- {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == sType {
				key := str.QueryAt(int(sufIdx))
				bucketBounds[key]--
				sa[bucketBounds[key]] = sufIdx
			}
		}
	}
	if slPartition.get(int(n)-1) == sType {
		key := str.QueryAt(int(n - 1))
		bucketBounds[key]--
		sa[bucketBounds[key]] = n - 1
	}
}

// seedOrderedLMSInPlace permutes the ordered LMS positions in sa[:m] into the
// tail of each symbol bucket. bucketBounds records the cumulative LMS count per
// symbol, while buckets is temporarily converted from counts to cumulative
// input counts. The target for sorted LMS rank r is bucketEnd[key]-lmsEnd[key]+r.
func seedOrderedLMSInPlace[S Uint32Source](str S, orderedLMS, buckets, bucketBounds, moved, sa []uint32) {
	clear(bucketBounds)
	for _, suffix := range orderedLMS {
		bucketBounds[str.QueryAt(int(suffix))]++
	}
	var lmsEnd uint32
	for key, count := range bucketBounds {
		lmsEnd += count
		bucketBounds[key] = lmsEnd
	}
	var bucketEnd uint32
	for key, count := range buckets {
		bucketEnd += count
		buckets[key] = bucketEnd
	}

	n := uint32(len(sa))
	m := len(orderedLMS)
	for i := m; i < len(sa); i++ {
		sa[i] = n
	}
	clear(moved)
	isMoved := func(rank int) bool {
		return moved[rank>>5]&(1<<uint(rank&31)) != 0
	}
	markMoved := func(rank int) {
		moved[rank>>5] |= 1 << uint(rank&31)
	}
	for rank := 0; rank < m; rank++ {
		if isMoved(rank) {
			continue
		}
		currentRank := rank
		suffix := sa[currentRank]
		for {
			key := str.QueryAt(int(suffix))
			destination := int(buckets[key] - bucketBounds[key] + uint32(currentRank))
			follow := destination < m && !isMoved(destination)
			var nextSuffix uint32
			if follow {
				nextSuffix = sa[destination]
			}
			sa[destination] = suffix
			markMoved(currentRank)
			if !follow {
				break
			}
			currentRank = destination
			suffix = nextSuffix
		}
	}

	cursor := 0
	var previousLmsEnd uint32
	for key, currentLmsEnd := range bucketBounds {
		count := int(currentLmsEnd - previousLmsEnd)
		seedEnd := int(buckets[key])
		seedBegin := seedEnd - count
		if seedBegin > cursor {
			clearEnd := min(seedBegin, m)
			for i := cursor; i < clearEnd; i++ {
				sa[i] = n
			}
		}
		if seedEnd > cursor {
			cursor = min(seedEnd, m)
		}
		previousLmsEnd = currentLmsEnd
		if cursor == m {
			break
		}
	}
	for i := cursor; i < m; i++ {
		sa[i] = n
	}

	var previousBucketEnd uint32
	for key, currentBucketEnd := range buckets {
		buckets[key] = currentBucketEnd - previousBucketEnd
		previousBucketEnd = currentBucketEnd
	}
}

func labelLmsSubstrings[S Uint32Source](str S, slPartition slBits, lmsRanks []uint32, sa []uint32, lmsLabels []uint32) int {
	if source, ok := any(str).(*ProjectionSource); ok {
		return labelLmsSubstringsProjection(source, slPartition, lmsRanks, sa, lmsLabels)
	}
	n := str.Size()
	label := 0
	var prevLms uint32 = 0

	for _, saVal := range sa {
		if saVal > 0 && slPartition.get(int(saVal)) == sType && slPartition.get(int(saVal)-1) == lType {
			curLms := saVal
			if prevLms != 0 {
				curLmsType := sType
				prevLmsType := sType
				for k := uint32(0); ; k++ {
					curEnd := false
					prevEnd := false

					if int(curLms+k) >= n || (curLmsType == lType && slPartition.get(int(curLms+k)) == sType) {
						curEnd = true
					}
					if int(prevLms+k) >= n || (prevLmsType == lType && slPartition.get(int(prevLms+k)) == sType) {
						prevEnd = true
					}

					if curEnd && prevEnd {
						break
					} else if curEnd != prevEnd || str.QueryAt(int(curLms+k)) != str.QueryAt(int(prevLms+k)) {
						label++
						break
					}

					curLmsType = slPartition.get(int(curLms + k))
					prevLmsType = slPartition.get(int(prevLms + k))
				}
			}
			lmsLabels[lmsRank(slPartition, lmsRanks, int(saVal))] = uint32(label)
			prevLms = curLms
		}
	}
	return label + 1
}

// SuffixLowerBound performs binary search in suffix array sa of str1 for target query.
func SuffixLowerBound(sa []uint32, str1 []byte, query []byte) int {
	n := len(sa)
	return sort.Search(n, func(i int) bool {
		idx := sa[i]
		suf := str1[idx:]
		return bytes.Compare(suf, query) >= 0
	})
}

// SuffixLowerBoundUint32 performs binary search in suffix array sa of oldProj for newProj[dstOffset:].
func SuffixLowerBoundUint32(sa []uint32, oldProj []uint32, newProj []uint32, dstOffset int) int {
	n := len(sa)
	query := newProj[dstOffset:]
	return sort.Search(n, func(i int) bool {
		idx := sa[i]
		suf := oldProj[idx:]
		minLen := min(len(query), len(suf))
		for k := 0; k < minLen; k++ {
			if suf[k] != query[k] {
				return suf[k] >= query[k]
			}
		}
		return len(suf) >= len(query)
	})
}

// QueryAt supplies query characters by absolute position, letting
// SuffixLowerBoundLazy run without a materialized query string.
type QueryAt interface {
	QueryAt(i int) uint32
}

// SuffixLowerBoundLazy is SuffixLowerBoundUint32 with the query drawn lazily
// from q over [queryLo, queryEnd). The haystack oldProj stays materialized,
// since it is also the suffix-sorted string; only the query is computed on
// demand. Comparisons stop at the first mismatch, so the number of QueryAt
// calls is small relative to a full projection array.
func SuffixLowerBoundLazy(sa []uint32, oldProj []uint32, q QueryAt, queryLo, queryEnd int) int {
	n := len(sa)
	queryLen := queryEnd - queryLo
	return sort.Search(n, func(i int) bool {
		idx := sa[i]
		suf := oldProj[idx:]
		minLen := min(queryLen, len(suf))
		for k := 0; k < minLen; k++ {
			qv := q.QueryAt(queryLo + k)
			if suf[k] != qv {
				return suf[k] >= qv
			}
		}
		return len(suf) >= queryLen
	})
}

// SuffixLowerBoundSource finds the lower bound of query[queryLo:queryEnd] in
// the suffix array of old. Both strings remain in their compact source form.
func SuffixLowerBoundSource[H, Q Uint32Source](sa []uint32, old H, query Q, queryLo, queryEnd int) int {
	queryLen := queryEnd - queryLo
	return sort.Search(len(sa), func(i int) bool {
		idx := int(sa[i])
		oldSuffixLen := old.Size() - idx
		minLen := min(queryLen, oldSuffixLen)
		for k := range minLen {
			oldValue := old.QueryAt(idx + k)
			queryValue := query.QueryAt(queryLo + k)
			if oldValue != queryValue {
				return oldValue >= queryValue
			}
		}
		return oldSuffixLen >= queryLen
	})
}
