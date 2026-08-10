package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type arm64AddrType uint8

const (
	arm64Immd14 arm64AddrType = iota
	arm64Immd19
	arm64Immd26
)

func signedBits(code uint32, lo, hi uint) int32 {
	width := hi - lo + 1
	return int32(code<<(32-hi-1)) >> (32 - width)
}

func signedFits(value int32, bits uint) bool {
	limit := int64(1) << (bits - 1)
	v := int64(value)
	return v >= -limit && v < limit
}

func decodeArm64(kind arm64AddrType, code uint32) (int32, bool) {
	switch kind {
	case arm64Immd14:
		bits := code & 0x7F000000
		if bits == 0x36000000 || bits == 0x37000000 {
			return signedBits(code, 5, 18) << 2, true
		}
	case arm64Immd19:
		bits1 := code & 0xFF000010
		bits2 := code & 0x7F000000
		if bits1 == 0x54000000 || bits2 == 0x34000000 || bits2 == 0x35000000 {
			return signedBits(code, 5, 23) << 2, true
		}
	case arm64Immd26:
		bits := code & 0xFC000000
		if bits == 0x14000000 || bits == 0x94000000 {
			return signedBits(code, 0, 25) << 2, true
		}
	}
	return 0, false
}

func encodeArm64(kind arm64AddrType, disp int32, code uint32) (uint32, bool) {
	if disp&3 != 0 {
		return code, false
	}
	switch kind {
	case arm64Immd14:
		bits := code & 0x7F000000
		if (bits == 0x36000000 || bits == 0x37000000) && signedFits(disp, 16) {
			return (code & 0xFFF8001F) | ((uint32(disp) >> 2 & 0x3FFF) << 5), true
		}
	case arm64Immd19:
		bits1 := code & 0xFF000010
		bits2 := code & 0x7F000000
		if (bits1 == 0x54000000 || bits2 == 0x34000000 || bits2 == 0x35000000) && signedFits(disp, 21) {
			return (code & 0xFF00001F) | ((uint32(disp) >> 2 & 0x7FFFF) << 5), true
		}
	case arm64Immd26:
		bits := code & 0xFC000000
		if (bits == 0x14000000 || bits == 0x94000000) && signedFits(disp, 28) {
			return (code & 0xFC000000) | (uint32(disp) >> 2 & 0x3FFFFFF), true
		}
	}
	return code, false
}

func readArm64(kind arm64AddrType, instrRVA types.RVA, code uint32) (types.RVA, bool) {
	if instrRVA&3 != 0 {
		return types.InvalidRVA, false
	}
	disp, ok := decodeArm64(kind, code)
	if !ok {
		return types.InvalidRVA, false
	}
	return instrRVA + types.RVA(disp), true
}

func writeArm64(kind arm64AddrType, instrRVA, targetRVA types.RVA, code uint32) (uint32, bool) {
	if instrRVA&3 != 0 || targetRVA&3 != 0 {
		return code, false
	}
	return encodeArm64(kind, int32(targetRVA-instrRVA), code)
}

type rel32ReaderArm64 struct {
	kind       arm64AddrType
	translator AddressTranslator
	image      []byte
	locations  []types.Offset
	index      int
	upper      types.Offset
}

func newRel32ReaderArm64(kind arm64AddrType, translator AddressTranslator, image []byte, locations []types.Offset, lower, upper types.Offset) *rel32ReaderArm64 {
	return &rel32ReaderArm64{
		kind: kind, translator: translator, image: image, locations: locations,
		index: sort.Search(len(locations), func(i int) bool { return locations[i] >= lower }), upper: upper,
	}
}

func (r *rel32ReaderArm64) GetNext() (types.Reference, bool) {
	for r.index < len(r.locations) && r.locations[r.index] < r.upper {
		location := r.locations[r.index]
		r.index++
		if int(location)+4 > len(r.image) {
			continue
		}
		instrRVA := r.translator.OffsetToRVA(location)
		targetRVA, ok := readArm64(r.kind, instrRVA, binary.LittleEndian.Uint32(r.image[location:]))
		if !ok {
			continue
		}
		target := r.translator.RVAToOffset(targetRVA)
		if target != types.InvalidOffset {
			return types.Reference{Location: location, Target: target}, true
		}
	}
	return types.Reference{}, false
}

type rel32WriterArm64 struct {
	kind       arm64AddrType
	translator AddressTranslator
	image      []byte
}

func (w *rel32WriterArm64) PutNext(ref types.Reference) {
	if int(ref.Location)+4 > len(w.image) {
		return
	}
	instrRVA := w.translator.OffsetToRVA(ref.Location)
	targetRVA := w.translator.OffsetToRVA(ref.Target)
	code := binary.LittleEndian.Uint32(w.image[ref.Location:])
	if code, ok := writeArm64(w.kind, instrRVA, targetRVA, code); ok {
		binary.LittleEndian.PutUint32(w.image[ref.Location:], code)
	}
}

type rel32MixerArm64 struct {
	kind     arm64AddrType
	oldImage []byte
	newImage []byte
	buffer   [4]byte
}

func (m *rel32MixerArm64) Mix(srcOffset, dstOffset types.Offset) []byte {
	newCode := binary.LittleEndian.Uint32(m.newImage[dstOffset:])
	oldCode := binary.LittleEndian.Uint32(m.oldImage[srcOffset:])
	if disp, ok := decodeArm64(m.kind, oldCode); ok {
		if mixed, ok := encodeArm64(m.kind, disp, newCode); ok {
			newCode = mixed
		}
	}
	binary.LittleEndian.PutUint32(m.buffer[:], newCode)
	return m.buffer[:]
}

func findArm64Rel32(image []byte, translator AddressTranslator, execSections []elfSection, abs32Locations []types.Offset, width int) [3][]types.Offset {
	var locations [3][]types.Offset
	for _, section := range execSections {
		gapFinder := NewAbs32GapFinder(image, types.BufferRegion{Offset: int(section.offset), Size: int(section.size)}, abs32Locations, width)
		for gapFinder.FindNext() {
			gap := gapFinder.GetGap()
			cursor := (gap.Offset + 3) &^ 3
			for cursor+4 <= gap.Hi() {
				location := types.Offset(cursor)
				instrRVA := translator.OffsetToRVA(location)
				code := binary.LittleEndian.Uint32(image[cursor:])
				for kind := arm64Immd14; kind <= arm64Immd26; kind++ {
					targetRVA, ok := readArm64(kind, instrRVA, code)
					if !ok {
						continue
					}
					target := translator.RVAToOffset(targetRVA)
					if target != types.InvalidOffset && offsetInExecSections(target, execSections) {
						locations[kind] = append(locations[kind], location)
					}
					break
				}
				cursor += 4
			}
		}
	}
	return locations
}

func offsetInExecSections(offset types.Offset, sections []elfSection) bool {
	i := sort.Search(len(sections), func(i int) bool { return sections[i].offset > uint64(offset) })
	if i == 0 {
		return false
	}
	section := sections[i-1]
	return uint64(offset) >= section.offset && uint64(offset) < section.offset+section.size
}
