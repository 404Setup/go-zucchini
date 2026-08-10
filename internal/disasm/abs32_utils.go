package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type AddressTranslator interface {
	OffsetToRVA(offset types.Offset) types.RVA
	RVAToOffset(rva types.RVA) types.Offset
}

type AbsoluteAddress struct {
	Bitness types.Bitness
	Base    uint64
}

func NewAbsoluteAddress(bitness types.Bitness, base uint64) AbsoluteAddress {
	return AbsoluteAddress{Bitness: bitness, Base: base}
}

func (a AbsoluteAddress) Read(image []byte, location types.Offset) (types.RVA, bool) {
	loc := int(location)
	width := int(a.Bitness.Width())
	if loc+width > len(image) {
		return types.InvalidRVA, false
	}
	var value uint64
	if a.Bitness == types.Bit32 {
		value = uint64(binary.LittleEndian.Uint32(image[loc:]))
	} else {
		value = binary.LittleEndian.Uint64(image[loc:])
	}

	if value < a.Base {
		return types.InvalidRVA, false
	}
	rva := value - a.Base
	if rva > uint64(types.InvalidRVA) {
		return types.InvalidRVA, false
	}
	return types.RVA(rva), true
}

func (a AbsoluteAddress) Write(image []byte, location types.Offset, rva types.RVA) bool {
	loc := int(location)
	width := int(a.Bitness.Width())
	if loc+width > len(image) {
		return false
	}
	value := a.Base + uint64(rva)
	if a.Bitness == types.Bit32 {
		binary.LittleEndian.PutUint32(image[loc:], uint32(value))
	} else {
		binary.LittleEndian.PutUint64(image[loc:], value)
	}
	return true
}

type Abs32RvaExtractorWin32 struct {
	image       []byte
	addr        AbsoluteAddress
	locations   []types.Offset
	curIdx      int
	upper       types.Offset
	curLocation types.Offset
}

func NewAbs32RvaExtractorWin32(
	image []byte,
	addr AbsoluteAddress,
	locations []types.Offset,
	lower, upper types.Offset,
) *Abs32RvaExtractorWin32 {
	idx := sort.Search(len(locations), func(i int) bool {
		return locations[i] >= lower
	})
	return &Abs32RvaExtractorWin32{
		image:     image,
		addr:      addr,
		locations: locations,
		curIdx:    idx,
		upper:     upper,
	}
}

func (e *Abs32RvaExtractorWin32) GetNext() (types.RVA, bool) {
	for e.curIdx < len(e.locations) && e.locations[e.curIdx] < e.upper {
		loc := e.locations[e.curIdx]
		e.curIdx++
		rva, ok := e.addr.Read(e.image, loc)
		if ok && rva != types.InvalidRVA {
			e.curLocation = loc
			return rva, true
		}
	}
	return types.InvalidRVA, false
}

func (e *Abs32RvaExtractorWin32) Location() types.Offset {
	return e.curLocation
}

type Abs32ReaderWin32 struct {
	extractor *Abs32RvaExtractorWin32
	trans     AddressTranslator
}

func NewAbs32ReaderWin32(extractor *Abs32RvaExtractorWin32, trans AddressTranslator) *Abs32ReaderWin32 {
	return &Abs32ReaderWin32{
		extractor: extractor,
		trans:     trans,
	}
}

func (r *Abs32ReaderWin32) GetNext() (types.Reference, bool) {
	for {
		rva, ok := r.extractor.GetNext()
		if !ok {
			return types.Reference{}, false
		}
		target := r.trans.RVAToOffset(rva)
		if target != types.InvalidOffset {
			return types.Reference{
				Location: r.extractor.Location(),
				Target:   target,
			}, true
		}
	}
}

type Abs32WriterWin32 struct {
	image []byte
	addr  AbsoluteAddress
	trans AddressTranslator
}

func NewAbs32WriterWin32(image []byte, addr AbsoluteAddress, trans AddressTranslator) *Abs32WriterWin32 {
	return &Abs32WriterWin32{
		image: image,
		addr:  addr,
		trans: trans,
	}
}

func (w *Abs32WriterWin32) PutNext(ref types.Reference) {
	rva := w.trans.OffsetToRVA(ref.Target)
	if rva != types.InvalidRVA {
		w.addr.Write(w.image, ref.Location, rva)
	}
}

func RemoveUntranslatableAbs32(image []byte, bitness types.Bitness, base uint64, trans AddressTranslator, locations *[]types.Offset) int {
	addr := NewAbsoluteAddress(bitness, base)
	extractor := NewAbs32RvaExtractorWin32(image, addr, *locations, 0, types.Offset(len(image)))
	reader := NewAbs32ReaderWin32(extractor, trans)

	filtered := (*locations)[:0]
	for {
		ref, ok := reader.GetNext()
		if !ok {
			break
		}
		filtered = append(filtered, ref.Location)
	}
	removed := len(*locations) - len(filtered)
	*locations = filtered
	return removed
}

func RemoveOverlappingAbs32Locations(width int, locations *[]types.Offset) int {
	locs := *locations
	if len(locs) <= 1 {
		return 0
	}
	filtered := locs[:1]
	for i := 1; i < len(locs); i++ {
		last := filtered[len(filtered)-1]
		if int(locs[i]-last) >= width {
			filtered = append(filtered, locs[i])
		}
	}
	removed := len(locs) - len(filtered)
	*locations = filtered
	return removed
}

type RvaToOffsetCache struct {
	trans AddressTranslator
}

func NewRvaToOffsetCache(trans AddressTranslator) *RvaToOffsetCache {
	return &RvaToOffsetCache{trans: trans}
}

func (c *RvaToOffsetCache) IsValid(rva types.RVA) bool {
	if rva == types.InvalidRVA {
		return false
	}
	return c.trans.RVAToOffset(rva) != types.InvalidOffset
}
