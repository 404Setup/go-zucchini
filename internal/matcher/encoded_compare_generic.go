//go:build !amd64 || !gc || purego || !asmcompare

package matcher

import "sort"

func suffixLowerBoundEncoded(sa []uint32, oldView, newView *EncodedView, queryLo int) int {
	queryLen := newView.Size() - queryLo
	return sort.Search(len(sa), func(i int) bool {
		idx := int(sa[i])
		oldSuffixLen := oldView.Size() - idx
		minLen := min(queryLen, oldSuffixLen)
		for k := 0; k < minLen; k++ {
			oldValue := oldView.QueryAt(idx + k)
			queryValue := newView.QueryAt(queryLo + k)
			if oldValue != queryValue {
				return oldValue >= queryValue
			}
		}
		return oldSuffixLen >= queryLen
	})
}
