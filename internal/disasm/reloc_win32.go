package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type RelocUnitWin32 struct {
	Location types.Offset
	Type     uint16
	RVA      types.RVA
}

const (
	relocHeaderSize = 8
	relocUnitSize   = 2
)

func FindRelocBlocks(image []byte, region types.BufferRegion, blockOffsets *[]types.Offset) bool {
	*blockOffsets = nil
	if region.Offset < 0 || region.Size < 0 || region.Offset > len(image) || region.Size > len(image)-region.Offset {
		return false
	}
	offset := region.Offset
	end := region.Hi()

	for offset <= end-relocHeaderSize {
		blockSize := binary.LittleEndian.Uint32(image[offset+4:])
		// Block size must be at least a header and 4-byte aligned.
		if blockSize < relocHeaderSize || blockSize%4 != 0 || uint64(blockSize) > uint64(end-offset) {
			return false
		}
		*blockOffsets = append(*blockOffsets, types.Offset(offset))
		offset += int(blockSize)
	}
	return offset == end
}

// RelocRvaReaderWin32 walks reloc units in [lower, upper). Blocks are traversed
// contiguously from the block *containing* lower, and the cursor is advanced to
// lower within that block, so a range starting mid-block yields exactly the
// units at or after lower.
type RelocRvaReaderWin32 struct {
	image     []byte
	hi        types.Offset // Exclusive upper bound for unit locations.
	rvaHiBits uint32       // Page RVA of the current block.
	cursor    types.Offset // Next unit location.
	blockEnd  types.Offset // End of the current block.
	curUnit   RelocUnitWin32
}

func NewRelocRvaReaderWin32(
	image []byte,
	region types.BufferRegion,
	blockOffsets []types.Offset,
	lower, upper types.Offset,
) *RelocRvaReaderWin32 {
	if lower > upper {
		lower = upper
	}
	clamp := func(v types.Offset) types.Offset {
		if lo := types.Offset(region.Offset); v < lo {
			return lo
		}
		if hi := types.Offset(region.Hi()); v > hi {
			return hi
		}
		return v
	}
	lo := clamp(lower)
	hi := clamp(upper)

	r := &RelocRvaReaderWin32{image: image, hi: hi, cursor: hi, blockEnd: hi}
	if len(blockOffsets) == 0 {
		return r
	}

	idx := sort.Search(len(blockOffsets), func(i int) bool {
		return blockOffsets[i] > lo
	})
	if idx == 0 {
		return r
	}
	if !r.loadRelocBlock(blockOffsets[idx-1]) {
		return r
	}

	if lo > r.cursor {
		delta := lo - r.cursor
		delta = (delta + relocUnitSize - 1) / relocUnitSize * relocUnitSize
		if avail := r.blockEnd - r.cursor; delta > avail {
			delta = avail
		}
		r.cursor += delta
	}
	return r
}

// loadRelocBlock points the reader at the block starting at blockBegin,
// returning false when no block with at least one readable unit fits.
func (r *RelocRvaReaderWin32) loadRelocBlock(blockBegin types.Offset) bool {
	headerEnd := int64(blockBegin) + relocHeaderSize
	if headerEnd+relocUnitSize > int64(r.hi) || headerEnd > int64(len(r.image)) {
		return false
	}
	blockSize := binary.LittleEndian.Uint32(r.image[blockBegin+4:])
	if blockSize < relocHeaderSize || (blockSize-relocHeaderSize)%relocUnitSize != 0 {
		return false
	}
	if int64(blockBegin)+int64(blockSize) > int64(len(r.image)) {
		return false
	}
	r.rvaHiBits = binary.LittleEndian.Uint32(r.image[blockBegin:])
	r.cursor = types.Offset(headerEnd)
	r.blockEnd = blockBegin + types.Offset(blockSize)
	return true
}

func (r *RelocRvaReaderWin32) GetNext() bool {
	// Outer loop over blocks, which are laid out contiguously.
	for int64(r.blockEnd)-int64(r.cursor) < relocUnitSize {
		if !r.loadRelocBlock(r.blockEnd) {
			return false
		}
	}
	if int64(r.hi)-int64(r.cursor) < relocUnitSize {
		return false
	}
	loc := r.cursor
	if int(loc)+relocUnitSize > len(r.image) {
		return false
	}
	entry := binary.LittleEndian.Uint16(r.image[loc:])
	r.cursor += relocUnitSize
	r.curUnit = RelocUnitWin32{
		Location: loc,
		Type:     entry >> 12,
		RVA:      types.RVA(r.rvaHiBits + uint32(entry&0x0FFF)),
	}
	return true
}

func (r *RelocRvaReaderWin32) Unit() RelocUnitWin32 {
	return r.curUnit
}

type RelocReaderWin32 struct {
	rvaReader   *RelocRvaReaderWin32
	relocType   uint16
	offsetBound types.Offset
	trans       AddressTranslator
}

func NewRelocReaderWin32(
	rvaReader *RelocRvaReaderWin32,
	relocType uint16,
	offsetBound types.Offset,
	trans AddressTranslator,
) *RelocReaderWin32 {
	return &RelocReaderWin32{
		rvaReader:   rvaReader,
		relocType:   relocType,
		offsetBound: offsetBound,
		trans:       trans,
	}
}

func (r *RelocReaderWin32) GetNext() (types.Reference, bool) {
	for r.rvaReader.GetNext() {
		unit := r.rvaReader.Unit()
		if unit.Type != r.relocType {
			continue
		}
		target := r.trans.RVAToOffset(unit.RVA)
		if target == types.InvalidOffset {
			continue
		}
		// Ensure the abs32 reference body fits entirely within the image.
		if target >= r.offsetBound {
			continue
		}
		return types.Reference{
			Location: unit.Location,
			Target:   target,
		}, true
	}
	return types.Reference{}, false
}

type RelocWriterWin32 struct {
	relocType    uint16
	image        []byte
	region       types.BufferRegion
	blockOffsets []types.Offset
	trans        AddressTranslator
}

func NewRelocWriterWin32(
	relocType uint16,
	image []byte,
	region types.BufferRegion,
	blockOffsets []types.Offset,
	trans AddressTranslator,
) *RelocWriterWin32 {
	return &RelocWriterWin32{
		relocType:    relocType,
		image:        image,
		region:       region,
		blockOffsets: blockOffsets,
		trans:        trans,
	}
}

func (w *RelocWriterWin32) PutNext(ref types.Reference) {
	rva := w.trans.OffsetToRVA(ref.Target)
	if rva != types.InvalidRVA && int(ref.Location)+2 <= len(w.image) {
		offsetInPage := uint16(rva & 0x0FFF)
		entry := (w.relocType << 12) | offsetInPage
		binary.LittleEndian.PutUint16(w.image[ref.Location:], entry)
	}
}
