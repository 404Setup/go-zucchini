package sais

func buildSLPartitionProjection(str *ProjectionSource, keyBound int, slPartition slBits) int {
	lmsCount := 0
	prevType := lType
	prevKey := uint32(keyBound)
	for i := len(str.image) - 1; i >= 0; i-- {
		curKey, ordinary := str.queryOrdinary(i)
		if !ordinary {
			curKey = str.referenceProjectionCold(i)
		}
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

func countBucketsProjection(str *ProjectionSource, buckets []uint32) {
	for i := range str.image {
		key, ordinary := str.queryOrdinary(i)
		if !ordinary {
			key = str.referenceProjectionCold(i)
		}
		buckets[key]++
	}
}

func labelLmsSubstringsProjection(str *ProjectionSource, slPartition slBits, lmsRanks, sa, lmsLabels []uint32) int {
	n := len(str.image)
	label := 0
	var prevLms uint32
	for _, saVal := range sa {
		if saVal == 0 || slPartition.get(int(saVal)) != sType || slPartition.get(int(saVal)-1) != lType {
			continue
		}
		curLms := saVal
		if prevLms != 0 {
			curLmsType := sType
			prevLmsType := sType
			for k := uint32(0); ; k++ {
				curEnd := int(curLms+k) >= n || (curLmsType == lType && slPartition.get(int(curLms+k)) == sType)
				prevEnd := int(prevLms+k) >= n || (prevLmsType == lType && slPartition.get(int(prevLms+k)) == sType)
				if curEnd && prevEnd {
					break
				}
				if curEnd != prevEnd {
					label++
					break
				}
				curKey, curOrdinary := str.queryOrdinary(int(curLms + k))
				if !curOrdinary {
					curKey = str.referenceProjectionCold(int(curLms + k))
				}
				prevKey, prevOrdinary := str.queryOrdinary(int(prevLms + k))
				if !prevOrdinary {
					prevKey = str.referenceProjectionCold(int(prevLms + k))
				}
				if curKey != prevKey {
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
	return label + 1
}

func prepareInducedSort(n uint32, buckets, bucketBounds, sa []uint32) []uint32 {
	for i := range sa {
		sa[i] = n
	}
	if len(bucketBounds) < len(buckets) {
		return make([]uint32, len(buckets))
	}
	return bucketBounds[:len(buckets)]
}

func bucketEnds(buckets, bounds []uint32) {
	var sum uint32
	for i, count := range buckets {
		sum += count
		bounds[i] = sum
	}
}

func bucketBegins(buckets, bounds []uint32) {
	bounds[0] = 0
	var sum uint32
	for i := 0; i < len(buckets)-1; i++ {
		sum += buckets[i]
		bounds[i+1] = sum
	}
}

func inducedSortBytes(str byteSlice, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str))
	bucketBounds = prepareInducedSort(n, buckets, bucketBounds, sa)
	bucketEnds(buckets, bucketBounds)
	for i := int(n) - 1; i > 0; i-- {
		if slPartition.get(i) == sType && slPartition.get(i-1) == lType {
			key := uint32(str[i])
			bucketBounds[key]--
			sa[bucketBounds[key]] = uint32(i)
		}
	}
	induceSeededBytes(str, slPartition, buckets, bucketBounds, sa)
}

func induceSeededBytes(str byteSlice, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str))
	bucketBegins(buckets, bucketBounds)
	if slPartition.get(int(n)-1) == lType {
		key := uint32(str[n-1])
		sa[bucketBounds[key]] = n - 1
		bucketBounds[key]++
	}
	for i := range n {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == lType {
				key := uint32(str[sufIdx])
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
				key := uint32(str[sufIdx])
				bucketBounds[key]--
				sa[bucketBounds[key]] = sufIdx
			}
		}
	}
	if slPartition.get(int(n)-1) == sType {
		key := uint32(str[n-1])
		bucketBounds[key]--
		sa[bucketBounds[key]] = n - 1
	}
}

func inducedSortUint32s(str uint32Slice, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str))
	bucketBounds = prepareInducedSort(n, buckets, bucketBounds, sa)
	bucketEnds(buckets, bucketBounds)
	for i := int(n) - 1; i > 0; i-- {
		if slPartition.get(i) == sType && slPartition.get(i-1) == lType {
			key := str[i]
			bucketBounds[key]--
			sa[bucketBounds[key]] = uint32(i)
		}
	}
	induceSeededUint32s(str, slPartition, buckets, bucketBounds, sa)
}

func induceSeededUint32s(str uint32Slice, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str))
	bucketBegins(buckets, bucketBounds)
	if slPartition.get(int(n)-1) == lType {
		key := str[n-1]
		sa[bucketBounds[key]] = n - 1
		bucketBounds[key]++
	}
	for i := range n {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == lType {
				key := str[sufIdx]
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
				key := str[sufIdx]
				bucketBounds[key]--
				sa[bucketBounds[key]] = sufIdx
			}
		}
	}
	if slPartition.get(int(n)-1) == sType {
		key := str[n-1]
		bucketBounds[key]--
		sa[bucketBounds[key]] = n - 1
	}
}

func inducedSortProjection(str *ProjectionSource, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str.image))
	bucketBounds = prepareInducedSort(n, buckets, bucketBounds, sa)
	bucketEnds(buckets, bucketBounds)
	for i := int(n) - 1; i > 0; i-- {
		if slPartition.get(i) == sType && slPartition.get(i-1) == lType {
			key, ordinary := str.queryOrdinary(i)
			if !ordinary {
				key = str.referenceProjectionCold(i)
			}
			bucketBounds[key]--
			sa[bucketBounds[key]] = uint32(i)
		}
	}
	induceSeededProjection(str, slPartition, buckets, bucketBounds, sa)
}

func induceSeededProjection(str *ProjectionSource, slPartition slBits, buckets, bucketBounds, sa []uint32) {
	n := uint32(len(str.image))
	bucketBegins(buckets, bucketBounds)
	if slPartition.get(int(n)-1) == lType {
		key, ordinary := str.queryOrdinary(int(n - 1))
		if !ordinary {
			key = str.referenceProjectionCold(int(n - 1))
		}
		sa[bucketBounds[key]] = n - 1
		bucketBounds[key]++
	}
	for i := range n {
		sufIdx := sa[i]
		if sufIdx != n && sufIdx > 0 {
			sufIdx--
			if slPartition.get(int(sufIdx)) == lType {
				key, ordinary := str.queryOrdinary(int(sufIdx))
				if !ordinary {
					key = str.referenceProjectionCold(int(sufIdx))
				}
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
				key, ordinary := str.queryOrdinary(int(sufIdx))
				if !ordinary {
					key = str.referenceProjectionCold(int(sufIdx))
				}
				bucketBounds[key]--
				sa[bucketBounds[key]] = sufIdx
			}
		}
	}
	if slPartition.get(int(n)-1) == sType {
		key, ordinary := str.queryOrdinary(int(n - 1))
		if !ordinary {
			key = str.referenceProjectionCold(int(n - 1))
		}
		bucketBounds[key]--
		sa[bucketBounds[key]] = n - 1
	}
}
