package disasm

import (
	"encoding/binary"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type arm32AddrType uint8

const (
	arm32A24 arm32AddrType = iota
	arm32T8
	arm32T11
	arm32T20
	arm32T24
)

func arm32Width(kind arm32AddrType) int {
	if kind == arm32T8 || kind == arm32T11 {
		return 2
	}
	return 4
}

func fetchArm32(kind arm32AddrType, image []byte, offset types.Offset) uint32 {
	i := int(offset)
	if kind == arm32T8 || kind == arm32T11 {
		return uint32(binary.LittleEndian.Uint16(image[i:]))
	}
	if kind == arm32T20 || kind == arm32T24 {
		return uint32(binary.LittleEndian.Uint16(image[i:]))<<16 | uint32(binary.LittleEndian.Uint16(image[i+2:]))
	}
	return binary.LittleEndian.Uint32(image[i:])
}

func storeArm32(kind arm32AddrType, image []byte, offset types.Offset, code uint32) {
	i := int(offset)
	if kind == arm32T8 || kind == arm32T11 {
		binary.LittleEndian.PutUint16(image[i:], uint16(code))
	} else if kind == arm32T20 || kind == arm32T24 {
		binary.LittleEndian.PutUint16(image[i:], uint16(code>>16))
		binary.LittleEndian.PutUint16(image[i+2:], uint16(code))
	} else {
		binary.LittleEndian.PutUint32(image[i:], code)
	}
}

func decodeArm32(kind arm32AddrType, code uint32) (disp int32, align uint32, ok bool) {
	switch kind {
	case arm32A24:
		bits := (code >> 24) & 0xF
		if bits == 0xA || bits == 0xB {
			disp = signedBits(code, 0, 23) << 2
			align = 4
			if code>>28 == 0xF {
				disp |= int32((code >> 24) & 1 << 1)
				align = 2
			}
			return disp, align, true
		}
	case arm32T8:
		if code&0xF000 == 0xD000 && code&0x0F00 != 0x0F00 {
			return signedBits(code, 0, 7) << 1, 2, true
		}
	case arm32T11:
		if code&0xF800 == 0xE000 {
			return signedBits(code, 0, 10) << 1, 2, true
		}
	case arm32T20:
		if code&0xF800D000 == 0xF0008000 && code&0x03C00000 != 0x03C00000 {
			imm11 := code & 0x7FF
			j2, j1 := (code>>11)&1, (code>>13)&1
			imm6, s := (code>>16)&0x3F, (code>>26)&1
			value := (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
			return int32(value<<11) >> 11, 2, true
		}
	case arm32T24:
		bits := code & 0xF800D000
		if bits == 0xF0009000 || bits == 0xF000D000 || bits == 0xF000C000 {
			imm11 := code & 0x7FF
			j2, j1 := (code>>11)&1, (code>>13)&1
			imm10, s := (code>>16)&0x3FF, (code>>26)&1
			value := (s << 24) | ((j1 ^ s ^ 1) << 23) | ((j2 ^ s ^ 1) << 22) | (imm10 << 12) | (imm11 << 1)
			align = 2
			if bits == 0xF000C000 {
				if code&1 != 0 {
					return 0, 0, false
				}
				align = 4
			}
			return int32(value<<7) >> 7, align, true
		}
	}
	return 0, 0, false
}

func encodeArm32(kind arm32AddrType, disp int32, code uint32) (uint32, bool) {
	switch kind {
	case arm32A24:
		bits := (code >> 24) & 0xF
		if (bits == 0xA || bits == 0xB) && signedFits(disp, 26) {
			if code>>28 == 0xF {
				if disp&1 != 0 {
					return code, false
				}
				code = code&0xFEFFFFFF | (uint32(disp>>1)&1)<<24
			} else if disp&3 != 0 {
				return code, false
			}
			return code&0xFF000000 | uint32(disp>>2)&0xFFFFFF, true
		}
	case arm32T8:
		if code&0xF000 == 0xD000 && code&0x0F00 != 0x0F00 && disp&1 == 0 && signedFits(disp, 9) {
			return code&0xFF00 | uint32(disp>>1)&0xFF, true
		}
	case arm32T11:
		if code&0xF800 == 0xE000 && disp&1 == 0 && signedFits(disp, 12) {
			return code&0xF800 | uint32(disp>>1)&0x7FF, true
		}
	case arm32T20:
		if code&0xF800D000 == 0xF0008000 && code&0x03C00000 != 0x03C00000 && disp&1 == 0 && signedFits(disp, 21) {
			u := uint32(disp)
			return code&0xFBC0D000 | ((u>>20)&1)<<26 | ((u>>12)&0x3F)<<16 | ((u>>18)&1)<<13 | ((u>>19)&1)<<11 | (u>>1)&0x7FF, true
		}
	case arm32T24:
		bits := code & 0xF800D000
		if (bits == 0xF0009000 || bits == 0xF000D000 || bits == 0xF000C000) && disp&1 == 0 && signedFits(disp, 25) {
			if bits == 0xF000C000 && disp&2 != 0 {
				return code, false
			}
			u := uint32(disp)
			s, i1, i2 := (u>>24)&1, (u>>23)&1, (u>>22)&1
			return code&0xF800D000 | s<<26 | ((u>>12)&0x3FF)<<16 | (i1^s^1)<<13 | (i2^s^1)<<11 | (u>>1)&0x7FF, true
		}
	}
	return code, false
}

func readArm32(kind arm32AddrType, instrRVA types.RVA, code uint32) (types.RVA, bool) {
	instrAlign := types.RVA(2)
	pcBias := types.RVA(4)
	if kind == arm32A24 {
		instrAlign, pcBias = 4, 8
	}
	if instrRVA%instrAlign != 0 {
		return types.InvalidRVA, false
	}
	disp, targetAlign, ok := decodeArm32(kind, code)
	if !ok {
		return types.InvalidRVA, false
	}
	target := instrRVA + pcBias + types.RVA(disp)
	return target &^ types.RVA(targetAlign-1), true
}

func writeArm32(kind arm32AddrType, instrRVA, targetRVA types.RVA, code uint32) (uint32, bool) {
	instrAlign := types.RVA(2)
	pcBias := types.RVA(4)
	if kind == arm32A24 {
		instrAlign, pcBias = 4, 8
	}
	_, targetAlign, ok := decodeArm32(kind, code)
	if !ok || instrRVA%instrAlign != 0 || targetRVA%types.RVA(targetAlign) != 0 {
		return code, false
	}
	disp := int32(targetRVA - (instrRVA + pcBias))
	disp += (-disp) & int32(targetAlign-1)
	return encodeArm32(kind, disp, code)
}

type rel32ReaderArm32 struct {
	kind       arm32AddrType
	translator AddressTranslator
	image      []byte
	locations  []types.Offset
	index      int
	upper      types.Offset
}

func newRel32ReaderArm32(kind arm32AddrType, translator AddressTranslator, image []byte, locations []types.Offset, lower, upper types.Offset) *rel32ReaderArm32 {
	return &rel32ReaderArm32{kind: kind, translator: translator, image: image, locations: locations, index: sort.Search(len(locations), func(i int) bool { return locations[i] >= lower }), upper: upper}
}
func (r *rel32ReaderArm32) GetNext() (types.Reference, bool) {
	for r.index < len(r.locations) && r.locations[r.index] < r.upper {
		loc := r.locations[r.index]
		r.index++
		targetRVA, ok := readArm32(r.kind, r.translator.OffsetToRVA(loc), fetchArm32(r.kind, r.image, loc))
		if ok {
			if target := r.translator.RVAToOffset(targetRVA); target != types.InvalidOffset {
				return types.Reference{Location: loc, Target: target}, true
			}
		}
	}
	return types.Reference{}, false
}

type rel32WriterArm32 struct {
	kind       arm32AddrType
	translator AddressTranslator
	image      []byte
}

func (w *rel32WriterArm32) PutNext(ref types.Reference) {
	code := fetchArm32(w.kind, w.image, ref.Location)
	if code, ok := writeArm32(w.kind, w.translator.OffsetToRVA(ref.Location), w.translator.OffsetToRVA(ref.Target), code); ok {
		storeArm32(w.kind, w.image, ref.Location, code)
	}
}

type rel32MixerArm32 struct {
	kind               arm32AddrType
	oldImage, newImage []byte
	buffer             [4]byte
}

func (m *rel32MixerArm32) Mix(srcOffset, dstOffset types.Offset) []byte {
	newCode, oldCode := fetchArm32(m.kind, m.newImage, dstOffset), fetchArm32(m.kind, m.oldImage, srcOffset)
	if disp, _, ok := decodeArm32(m.kind, oldCode); ok {
		if mixed, ok := encodeArm32(m.kind, disp, newCode); ok {
			newCode = mixed
		}
	}
	width := arm32Width(m.kind)
	clear(m.buffer[:])
	storeArm32(m.kind, m.buffer[:width], 0, newCode)
	return m.buffer[:width]
}

func findArm32Rel32(image []byte, translator AddressTranslator, execSections []elfSection, abs32 []types.Offset, width int) [5][]types.Offset {
	var locations [5][]types.Offset
	for _, section := range execSections {
		thumb := section.addr%4 != 0 || section.size%4 != 0
		if !thumb {
			always := 0
			for i := int(section.offset); i < int(section.offset+section.size); i += 4 {
				if image[i+3]&0xF0 == 0xE0 {
					always++
				}
			}
			thumb = always*10 < int(section.size/4)*4
		}
		gaps := NewAbs32GapFinder(image, types.BufferRegion{Offset: int(section.offset), Size: int(section.size)}, abs32, width)
		for gaps.FindNext() {
			gap := gaps.GetGap()
			align := 4
			if thumb {
				align = 2
			}
			cursor := (gap.Offset + align - 1) &^ (align - 1)
			for cursor+align <= gap.Hi() {
				loc := types.Offset(cursor)
				instrRVA := translator.OffsetToRVA(loc)
				if !thumb {
					if target, ok := readArm32(arm32A24, instrRVA, fetchArm32(arm32A24, image, loc)); ok {
						if off := translator.RVAToOffset(target); off != types.InvalidOffset && offsetInExecSections(off, execSections) {
							locations[arm32A24] = append(locations[arm32A24], loc)
						}
					}
					cursor += 4
					continue
				}
				code16 := binary.LittleEndian.Uint16(image[cursor:])
				instrSize := 2
				if code16&0xF000 == 0xF000 || code16&0xF800 == 0xE800 {
					instrSize = 4
				}
				if cursor+instrSize > gap.Hi() {
					break
				}
				kinds := []arm32AddrType{arm32T8, arm32T11}
				if instrSize == 4 {
					kinds = []arm32AddrType{arm32T20, arm32T24}
				}
				for _, kind := range kinds {
					target, ok := readArm32(kind, instrRVA, fetchArm32(kind, image, loc))
					if !ok {
						continue
					}
					if off := translator.RVAToOffset(target); off != types.InvalidOffset && offsetInExecSections(off, execSections) {
						locations[kind] = append(locations[kind], loc)
					}
					break
				}
				cursor += instrSize
			}
		}
	}
	return locations
}
