package disasm

import (
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type AddressTranslatorStatus int

const (
	AddressTranslatorSuccess AddressTranslatorStatus = iota
	AddressTranslatorErrorOverflow
	AddressTranslatorErrorBadOverlap
	AddressTranslatorErrorBadOverlapDanglingRVA
	AddressTranslatorErrorFakeOffsetBeginTooLarge
)

func (s AddressTranslatorStatus) String() string {
	switch s {
	case AddressTranslatorSuccess:
		return "Success"
	case AddressTranslatorErrorOverflow:
		return "Overflow error"
	case AddressTranslatorErrorBadOverlap:
		return "Bad overlap error"
	case AddressTranslatorErrorBadOverlapDanglingRVA:
		return "Bad overlap dangling RVA error"
	case AddressTranslatorErrorFakeOffsetBeginTooLarge:
		return "Fake offset begin too large error"
	default:
		return "Unknown address translator status"
	}
}

// AddressTranslator translates between image file offsets and Relative Virtual Addresses (RVAs).
type AddressTranslatorStruct struct {
	unitsSortedByOffset []types.Unit
	unitsSortedByRVA    []types.Unit
	fakeOffsetBegin     types.Offset
}

func NewAddressTranslator() *AddressTranslatorStruct {
	return &AddressTranslatorStruct{}
}

func (at *AddressTranslatorStruct) FakeOffsetBegin() types.Offset {
	return at.fakeOffsetBegin
}

func (at *AddressTranslatorStruct) UnitsSortedByOffset() []types.Unit {
	return at.unitsSortedByOffset
}

func (at *AddressTranslatorStruct) UnitsSortedByRVA() []types.Unit {
	return at.unitsSortedByRVA
}

func (at *AddressTranslatorStruct) Initialize(units []types.Unit) AddressTranslatorStatus {
	processed := make([]types.Unit, len(units))
	copy(processed, units)

	for i := range processed {
		u := &processed[i]
		if !rangeIsBounded(u.OffsetBegin, u.OffsetSize, types.OffsetBound) ||
			!rangeIsBounded(u.RVABegin, u.RVASize, types.RVABound) {
			return AddressTranslatorErrorOverflow
		}
		if u.OffsetSize > types.Offset(u.RVASize) {
			u.OffsetSize = types.Offset(u.RVASize)
		}
	}

	var filtered []types.Unit
	for _, u := range processed {
		if !u.IsEmpty() {
			filtered = append(filtered, u)
		}
	}
	processed = filtered

	sort.Slice(processed, func(i, j int) bool {
		if processed[i].RVABegin != processed[j].RVABegin {
			return processed[i].RVABegin < processed[j].RVABegin
		}
		return processed[i].RVASize < processed[j].RVASize
	})

	if len(processed) > 0 {
		dedup := processed[:1]
		for i := 1; i < len(processed); i++ {
			if processed[i] != dedup[len(dedup)-1] {
				dedup = append(dedup, processed[i])
			}
		}
		processed = dedup
	}

	if len(processed) > 1 {
		slow := 0
		for fast := 1; fast < len(processed); fast++ {
			if processed[slow].RVAEnd() < processed[fast].RVABegin {
				slow++
				processed[slow] = processed[fast]
				continue
			}

			mergeOptional := processed[slow].RVAEnd() == processed[fast].RVABegin

			if processed[fast].OffsetBegin < processed[slow].OffsetBegin ||
				(processed[fast].OffsetBegin-processed[slow].OffsetBegin) != types.Offset(processed[fast].RVABegin-processed[slow].RVABegin) {
				if mergeOptional {
					slow++
					processed[slow] = processed[fast]
					continue
				}
				return AddressTranslatorErrorBadOverlap
			}

			if (processed[fast].HasDanglingRVA() && processed[fast].OffsetEnd() < processed[slow].OffsetEnd()) ||
				(processed[slow].HasDanglingRVA() && processed[slow].OffsetEnd() < processed[fast].OffsetEnd()) {
				if mergeOptional {
					slow++
					processed[slow] = processed[fast]
					continue
				}
				return AddressTranslatorErrorBadOverlapDanglingRVA
			}

			rvaEndSlow := processed[slow].RVAEnd()
			rvaEndFast := processed[fast].RVAEnd()
			if rvaEndFast > rvaEndSlow {
				processed[slow].RVASize = rvaEndFast - processed[slow].RVABegin
			}

			offEndSlow := processed[slow].OffsetEnd()
			offEndFast := processed[fast].OffsetEnd()
			if offEndFast > offEndSlow {
				processed[slow].OffsetSize = offEndFast - processed[slow].OffsetBegin
			}
		}
		processed = processed[:slow+1]
	}

	sort.Slice(processed, func(i, j int) bool {
		return processed[i].OffsetBegin < processed[j].OffsetBegin
	})

	if len(processed) > 1 {
		for i := 1; i < len(processed); i++ {
			if processed[i-1].OffsetEnd() > processed[i].OffsetBegin {
				return AddressTranslatorErrorBadOverlap
			}
		}
	}

	var offsetBound types.Offset
	var rvaBound types.RVA
	for _, u := range processed {
		if u.OffsetEnd() > offsetBound {
			offsetBound = u.OffsetEnd()
		}
		if u.RVAEnd() > rvaBound {
			rvaBound = u.RVAEnd()
		}
	}

	if !rangeIsBounded(offsetBound, types.Offset(rvaBound), types.OffsetBound) {
		return AddressTranslatorErrorFakeOffsetBeginTooLarge
	}

	at.unitsSortedByOffset = make([]types.Unit, len(processed))
	copy(at.unitsSortedByOffset, processed)

	sort.Slice(processed, func(i, j int) bool {
		return processed[i].RVABegin < processed[j].RVABegin
	})
	at.unitsSortedByRVA = processed
	at.fakeOffsetBegin = offsetBound

	return AddressTranslatorSuccess
}

func (at *AddressTranslatorStruct) OffsetToRVA(offset types.Offset) types.RVA {
	if offset >= at.fakeOffsetBegin {
		rva := types.RVA(offset - at.fakeOffsetBegin)
		u := at.RVAToUnit(rva)
		if u != nil && u.HasDanglingRVA() && u.CoversDanglingRVA(rva) {
			return rva
		}
		return types.InvalidRVA
	}
	u := at.OffsetToUnit(offset)
	if u == nil {
		return types.InvalidRVA
	}
	return u.OffsetToRVAUnsafe(offset)
}

func (at *AddressTranslatorStruct) RVAToOffset(rva types.RVA) types.Offset {
	u := at.RVAToUnit(rva)
	if u == nil {
		return types.InvalidOffset
	}
	return u.RVAToOffsetUnsafe(rva, at.fakeOffsetBegin)
}

func (at *AddressTranslatorStruct) OffsetToUnit(offset types.Offset) *types.Unit {
	idx := sort.Search(len(at.unitsSortedByOffset), func(i int) bool {
		return at.unitsSortedByOffset[i].OffsetBegin > offset
	})
	if idx == 0 {
		return nil
	}
	u := &at.unitsSortedByOffset[idx-1]
	if u.CoversOffset(offset) {
		return u
	}
	return nil
}

func (at *AddressTranslatorStruct) RVAToUnit(rva types.RVA) *types.Unit {
	idx := sort.Search(len(at.unitsSortedByRVA), func(i int) bool {
		return at.unitsSortedByRVA[i].RVABegin > rva
	})
	if idx == 0 {
		return nil
	}
	u := &at.unitsSortedByRVA[idx-1]
	if u.CoversRVA(rva) {
		return u
	}
	return nil
}

func rangeIsBounded[T ~uint32](begin, size, bound T) bool {
	return begin < bound && size <= bound-begin
}

// OffsetToRVACache caches last matched unit for clustered offset queries.
type OffsetToRVACache struct {
	translator AddressTranslator
	cachedUnit *types.Unit
}

func NewOffsetToRVACache(translator AddressTranslator) *OffsetToRVACache {
	return &OffsetToRVACache{translator: translator}
}

func (c *OffsetToRVACache) Convert(offset types.Offset) types.RVA {
	if at, ok := c.translator.(*AddressTranslatorStruct); ok {
		if offset >= at.fakeOffsetBegin {
			return c.translator.OffsetToRVA(offset)
		}
	}
	if c.cachedUnit != nil && c.cachedUnit.CoversOffset(offset) {
		return c.cachedUnit.OffsetToRVAUnsafe(offset)
	}
	if at, ok := c.translator.(*AddressTranslatorStruct); ok {
		u := at.OffsetToUnit(offset)
		if u == nil {
			return types.InvalidRVA
		}
		c.cachedUnit = u
		return u.OffsetToRVAUnsafe(offset)
	}
	return c.translator.OffsetToRVA(offset)
}

// RVAToOffsetCache caches last matched unit for clustered RVA queries.
type RVAToOffsetCache struct {
	translator AddressTranslator
	cachedUnit *types.Unit
}

func NewRVAToOffsetCache(translator AddressTranslator) *RVAToOffsetCache {
	return &RVAToOffsetCache{translator: translator}
}

func (c *RVAToOffsetCache) IsValid(rva types.RVA) bool {
	if rva == types.InvalidRVA {
		return false
	}
	if c.cachedUnit == nil || !c.cachedUnit.CoversRVA(rva) {
		if at, ok := c.translator.(*AddressTranslatorStruct); ok {
			u := at.RVAToUnit(rva)
			if u == nil {
				return false
			}
			c.cachedUnit = u
		} else {
			return c.translator.RVAToOffset(rva) != types.InvalidOffset
		}
	}
	return true
}

func (c *RVAToOffsetCache) Convert(rva types.RVA) types.Offset {
	if c.cachedUnit == nil || !c.cachedUnit.CoversRVA(rva) {
		if at, ok := c.translator.(*AddressTranslatorStruct); ok {
			u := at.RVAToUnit(rva)
			if u == nil {
				return types.InvalidOffset
			}
			c.cachedUnit = u
		} else {
			return c.translator.RVAToOffset(rva)
		}
	}
	if at, ok := c.translator.(*AddressTranslatorStruct); ok {
		return c.cachedUnit.RVAToOffsetUnsafe(rva, at.fakeOffsetBegin)
	}
	return c.translator.RVAToOffset(rva)
}
