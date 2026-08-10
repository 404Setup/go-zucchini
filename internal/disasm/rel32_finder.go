package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type Abs32GapFinder struct {
	image          []byte
	regionOffset   int
	regionSize     int
	abs32Locations []types.Offset
	abs32Width     int
	abs32CurIdx    int
	curLo          int
	gap            types.BufferRegion
}

func NewAbs32GapFinder(image []byte, region types.BufferRegion, abs32Locations []types.Offset, abs32Width int) *Abs32GapFinder {
	beginOffset := region.Offset
	curIdx := sort.Search(len(abs32Locations), func(i int) bool {
		return int(abs32Locations[i]) >= beginOffset
	})

	curLo := region.Offset
	if curIdx > 0 {
		prevEnd := int(abs32Locations[curIdx-1]) + abs32Width
		if prevEnd > curLo {
			curLo = prevEnd
		}
	}

	return &Abs32GapFinder{
		image:          image,
		regionOffset:   region.Offset,
		regionSize:     region.Size,
		abs32Locations: abs32Locations,
		abs32Width:     abs32Width,
		abs32CurIdx:    curIdx,
		curLo:          curLo,
	}
}

func (f *Abs32GapFinder) FindNext() bool {
	regionEnd := f.regionOffset + f.regionSize
	for f.abs32CurIdx < len(f.abs32Locations) && int(f.abs32Locations[f.abs32CurIdx]) < regionEnd {
		hi := int(f.abs32Locations[f.abs32CurIdx])
		if hi > f.curLo {
			f.gap = types.BufferRegion{Offset: f.curLo, Size: hi - f.curLo}
			f.curLo = hi + f.abs32Width
			f.abs32CurIdx++
			return true
		}
		f.curLo = hi + f.abs32Width
		f.abs32CurIdx++
	}

	if f.curLo < regionEnd {
		f.gap = types.BufferRegion{Offset: f.curLo, Size: regionEnd - f.curLo}
		f.curLo = regionEnd
		return true
	}
	return false
}

func (f *Abs32GapFinder) GetGap() types.BufferRegion {
	return f.gap
}

type OffsetToRVAConverter interface {
	OffsetToRVA(offset types.Offset) types.RVA
}

type Rel32IntelResult struct {
	Location               types.Offset
	TargetRVA              types.RVA
	CanPointOutsideSection bool
}

type Rel32FinderIntel struct {
	image        []byte
	offsetToRVA  OffsetToRVAConverter
	region       types.BufferRegion
	cursor       int
	acceptCursor int
	rel32        Rel32IntelResult
	isX64        bool
}

func NewRel32FinderX86(image []byte, trans AddressTranslator) *Rel32FinderIntel {
	return &Rel32FinderIntel{
		image:       image,
		offsetToRVA: trans,
		isX64:       false,
	}
}

func NewRel32FinderX64(image []byte, trans AddressTranslator) *Rel32FinderIntel {
	return &Rel32FinderIntel{
		image:       image,
		offsetToRVA: trans,
		isX64:       true,
	}
}

func (f *Rel32FinderIntel) SetRegion(region types.BufferRegion) {
	f.region = region
	f.cursor = region.Offset
	f.acceptCursor = region.Offset
}

func (f *Rel32FinderIntel) FindNext() bool {
	end := f.region.Hi()
	for f.cursor < end {
		if f.cursor+5 <= end {
			op := f.image[f.cursor]
			if op == 0xE8 || op == 0xE9 {
				f.setResult(f.cursor, 1, false)
				return true
			}
		}
		if f.cursor+6 <= end {
			op0 := f.image[f.cursor]
			op1 := f.image[f.cursor+1]
			if op0 == 0x0F && (op1&0xF0) == 0x80 {
				f.setResult(f.cursor, 2, false)
				return true
			}
			if f.isX64 {
				if (op0 == 0xFF && (op1 == 0x15 || op1 == 0x25)) ||
					((op0 == 0x89 || op0 == 0x8B || op0 == 0x8D) && (op1&0xC7) == 0x05) {
					f.setResult(f.cursor, 2, true)
					return true
				}
			}
		}
		f.cursor++
	}
	return false
}

func (f *Rel32FinderIntel) setResult(cursor int, opcodeSize int, canPointOutsideSection bool) {
	location := types.Offset(cursor + opcodeSize)
	locationRVA := f.offsetToRVA.OffsetToRVA(location)
	disp := binary.LittleEndian.Uint32(f.image[location:])
	targetRVA := locationRVA + 4 + types.RVA(disp)
	f.rel32 = Rel32IntelResult{
		Location:               location,
		TargetRVA:              targetRVA,
		CanPointOutsideSection: canPointOutsideSection,
	}
	f.acceptCursor = cursor + opcodeSize + 4
	f.cursor = cursor + 1
}

func (f *Rel32FinderIntel) Accept() {
	f.cursor = f.acceptCursor
}

func (f *Rel32FinderIntel) GetRel32() Rel32IntelResult {
	return f.rel32
}
