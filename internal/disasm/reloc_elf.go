package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type SectionDimensionsElf struct {
	Region    types.BufferRegion
	EntrySize types.Offset
}

type RelocReaderElf struct {
	image         []byte
	bitness       types.Bitness
	sections      []SectionDimensionsElf
	relType       uint32
	hi            types.Offset
	trans         AddressTranslator
	curSectionIdx int
	curOffset     types.Offset
}

func NewRelocReaderElf(
	image []byte,
	bitness types.Bitness,
	sections []SectionDimensionsElf,
	relType uint32,
	lower, upper types.Offset,
	trans AddressTranslator,
) *RelocReaderElf {
	r := &RelocReaderElf{
		image:    image,
		bitness:  bitness,
		sections: sections,
		relType:  relType,
		hi:       upper,
		trans:    trans,
	}
	if len(sections) == 0 {
		return r
	}

	r.curSectionIdx = sort.Search(len(sections), func(i int) bool {
		return types.Offset(sections[i].Region.Offset) > lower
	})
	if r.curSectionIdx > 0 {
		r.curSectionIdx--
	}
	sec := sections[r.curSectionIdx]
	r.curOffset = types.Offset(sec.Region.Offset)
	if entrySize := sec.EntrySize; entrySize > 0 && r.curOffset < lower {
		delta := lower - r.curOffset
		r.curOffset += (delta + entrySize - 1) / entrySize * entrySize
	}

	endIdx := sort.Search(len(sections), func(i int) bool {
		return types.Offset(sections[i].Region.Offset) > upper
	})
	if endIdx > 0 {
		endSec := sections[endIdx-1]
		begin := types.Offset(endSec.Region.Offset)
		size := types.Offset(endSec.Region.Size)
		if upper >= begin && upper-begin < size && endSec.EntrySize > 0 {
			delta := upper - begin
			r.hi = begin + (delta+endSec.EntrySize-1)/endSec.EntrySize*endSec.EntrySize
		}
	}
	return r
}

func (r *RelocReaderElf) GetNext() (types.Reference, bool) {
	for r.curSectionIdx < len(r.sections) {
		sec := r.sections[r.curSectionIdx]
		entrySize := sec.EntrySize
		if entrySize == 0 {
			r.curSectionIdx++
			continue
		}
		secBegin := types.Offset(sec.Region.Offset)
		secEnd := types.Offset(sec.Region.Hi())
		if r.curOffset < secBegin {
			r.curOffset = secBegin
		}
		if r.curOffset >= secEnd || r.curOffset+entrySize > secEnd {
			r.curSectionIdx++
			continue
		}
		if r.curOffset+entrySize > r.hi {
			return types.Reference{}, false
		}

		loc := int(r.curOffset)
		r.curOffset += entrySize

		var rOffset uint64
		var rInfo uint64

		if r.bitness == types.Bit32 {
			if loc+8 > len(r.image) {
				continue
			}
			rOffset = uint64(binary.LittleEndian.Uint32(r.image[loc:]))
			rInfo = uint64(binary.LittleEndian.Uint32(r.image[loc+4:]))
		} else {
			if loc+16 > len(r.image) {
				continue
			}
			rOffset = binary.LittleEndian.Uint64(r.image[loc:])
			rInfo = binary.LittleEndian.Uint64(r.image[loc+8:])
			if rOffset > uint64(^uint32(0)) {
				continue
			}
		}

		relType := uint32(rInfo & 0xFF)
		if r.bitness == types.Bit64 {
			relType = uint32(rInfo & 0xFFFFFFFF)
		}

		if relType == r.relType {
			target := r.trans.RVAToOffset(types.RVA(rOffset))
			width := uint64(r.bitness.Width())
			if target != types.InvalidOffset && uint64(target)+width <= uint64(len(r.image)) {
				return types.Reference{
					Location: types.Offset(loc),
					Target:   target,
				}, true
			}
		}
	}
	return types.Reference{}, false
}

type RelocWriterElf struct {
	image   []byte
	bitness types.Bitness
	trans   AddressTranslator
}

func NewRelocWriterElf(image []byte, bitness types.Bitness, trans AddressTranslator) *RelocWriterElf {
	return &RelocWriterElf{
		image:   image,
		bitness: bitness,
		trans:   trans,
	}
}

func (w *RelocWriterElf) PutNext(ref types.Reference) {
	rva := w.trans.OffsetToRVA(ref.Target)
	if rva != types.InvalidRVA {
		loc := int(ref.Location)
		if w.bitness == types.Bit32 {
			if loc+4 <= len(w.image) {
				binary.LittleEndian.PutUint32(w.image[loc:], uint32(rva))
			}
		} else {
			if loc+8 <= len(w.image) {
				binary.LittleEndian.PutUint64(w.image[loc:], uint64(rva))
			}
		}
	}
}
