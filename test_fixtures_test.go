package zucchini

import "encoding/binary"

// makeSyntheticPE64 builds a small, deterministic PE32+ image with a base
// relocation, absolute addresses, and relative branches. It exercises the PE
// paths without relying on binaries produced by another toolchain.
func makeSyntheticPE64(variant byte) []byte {
	image := make([]byte, 0x400)
	image[0], image[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(image[0x3C:], 0x80)
	copy(image[0x80:], []byte{'P', 'E', 0, 0})

	const (
		fileHeader     = 0x84
		optionalHeader = fileHeader + 20
		sectionHeader  = optionalHeader + 0xF0
		imageBase      = uint64(0x140000000)
	)
	binary.LittleEndian.PutUint16(image[fileHeader:], 0x8664)
	binary.LittleEndian.PutUint16(image[fileHeader+2:], 1)
	binary.LittleEndian.PutUint16(image[fileHeader+16:], 0xF0)
	binary.LittleEndian.PutUint16(image[optionalHeader:], 0x20B)
	binary.LittleEndian.PutUint64(image[optionalHeader+24:], imageBase)
	binary.LittleEndian.PutUint32(image[optionalHeader+56:], 0x2000)
	binary.LittleEndian.PutUint32(image[optionalHeader+60:], 0x200)
	binary.LittleEndian.PutUint32(image[optionalHeader+108:], 16)

	// Put the relocation directory near the end of the single mapped section.
	const relocationDirectory = optionalHeader + 112 + 5*8
	binary.LittleEndian.PutUint32(image[relocationDirectory:], 0x1180)
	binary.LittleEndian.PutUint32(image[relocationDirectory+4:], 12)

	copy(image[sectionHeader:], ".text")
	binary.LittleEndian.PutUint32(image[sectionHeader+8:], 0x200)
	binary.LittleEndian.PutUint32(image[sectionHeader+12:], 0x1000)
	binary.LittleEndian.PutUint32(image[sectionHeader+16:], 0x200)
	binary.LittleEndian.PutUint32(image[sectionHeader+20:], 0x200)
	binary.LittleEndian.PutUint32(image[sectionHeader+36:], 0x60000020)

	for i := 0x200; i < 0x400; i++ {
		image[i] = byte(i*29 + 7)
	}
	// CALL 0x1080 and JMP 0x10C0. The stored fields begin one byte after
	// each opcode and are the locations tracked by the rel32 disassembler.
	image[0x210] = 0xE8
	binary.LittleEndian.PutUint32(image[0x211:], uint32(0x1080-(0x1011+4)))
	image[0x240] = 0xE9
	binary.LittleEndian.PutUint32(image[0x241:], uint32(0x10C0-(0x1041+4)))

	// A DIR64 relocation at RVA 0x1100 points at an absolute address in the
	// same image. The zero entry pads the relocation block to 4-byte alignment.
	binary.LittleEndian.PutUint64(image[0x280:], imageBase+0x10C0)
	binary.LittleEndian.PutUint64(image[0x300:], imageBase+0x1080)
	binary.LittleEndian.PutUint32(image[0x380:], 0x1000)
	binary.LittleEndian.PutUint32(image[0x384:], 12)
	binary.LittleEndian.PutUint16(image[0x388:], 10<<12|0x100)
	binary.LittleEndian.PutUint16(image[0x38A:], 0)

	image[0x2A0] ^= variant
	image[0x2D0] += variant
	return image
}
