package buffer

import (
	"bytes"
	"encoding/binary"
)

const MaxLeb128Size = 5

// BufferSource acts like an input stream with convenience methods to parse data
// from a contiguous byte slice. It tracks a read cursor.
type BufferSource struct {
	data   []byte
	cursor int
}

// NewBufferSource creates a new BufferSource wrapping data.
func NewBufferSource(data []byte) *BufferSource {
	return &BufferSource{data: data, cursor: 0}
}

// NewBufferSourceFromOffset creates a BufferSource wrapping data, starting at offset.
func NewBufferSourceFromOffset(data []byte, offset int) *BufferSource {
	if offset < 0 {
		offset = 0
	}
	if offset > len(data) {
		offset = len(data)
	}
	return &BufferSource{data: data, cursor: offset}
}

func (b *BufferSource) Cursor() int {
	return b.cursor
}

func (b *BufferSource) RegionFrom(start int) []byte {
	if start < 0 || start > b.cursor {
		return nil
	}
	return b.data[start:b.cursor]
}

// Remaining returns the number of bytes remaining from the cursor to the end.
func (b *BufferSource) Remaining() int {
	return len(b.data) - b.cursor
}

// Bytes returns the remaining byte slice from the cursor.
func (b *BufferSource) Bytes() []byte {
	return b.data[b.cursor:]
}

// Skip advances the cursor by n bytes. Returns true if sufficient bytes remain,
// or false (and moves cursor to end) if requested size exceeds remaining bytes.
func (b *BufferSource) Skip(n int) bool {
	if n < 0 {
		return false
	}
	if n > b.Remaining() {
		b.cursor = len(b.data)
		return false
	}
	b.cursor += n
	return true
}

// CheckNextBytes returns true if the next bytes match the provided target slice.
func (b *BufferSource) CheckNextBytes(target []byte) bool {
	if b.Remaining() < len(target) {
		return false
	}
	return bytes.Equal(b.data[b.cursor:b.cursor+len(target)], target)
}

// ConsumeBytes checks if the next bytes match target. If so, advances cursor and returns true.
func (b *BufferSource) ConsumeBytes(target []byte) bool {
	if !b.CheckNextBytes(target) {
		return false
	}
	b.cursor += len(target)
	return true
}

// GetUint8 reads a 1-byte unsigned int and advances the cursor.
func (b *BufferSource) GetUint8() (uint8, bool) {
	if b.Remaining() < 1 {
		return 0, false
	}
	v := b.data[b.cursor]
	b.cursor++
	return v, true
}

// GetUint16LE reads a 2-byte little-endian unsigned int and advances the cursor.
func (b *BufferSource) GetUint16LE() (uint16, bool) {
	if b.Remaining() < 2 {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(b.data[b.cursor:])
	b.cursor += 2
	return v, true
}

// GetUint32LE reads a 4-byte little-endian unsigned int and advances the cursor.
func (b *BufferSource) GetUint32LE() (uint32, bool) {
	if b.Remaining() < 4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(b.data[b.cursor:])
	b.cursor += 4
	return v, true
}

// GetUint64LE reads an 8-byte little-endian unsigned int and advances the cursor.
func (b *BufferSource) GetUint64LE() (uint64, bool) {
	if b.Remaining() < 8 {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(b.data[b.cursor:])
	b.cursor += 8
	return v, true
}

// GetInt32LE reads a 4-byte little-endian signed int and advances the cursor.
func (b *BufferSource) GetInt32LE() (int32, bool) {
	u, ok := b.GetUint32LE()
	return int32(u), ok
}

// GetRegion returns a sub-slice of count bytes and advances the cursor.
func (b *BufferSource) GetRegion(count int) ([]byte, bool) {
	if count < 0 || b.Remaining() < count {
		return nil, false
	}
	reg := b.data[b.cursor : b.cursor+count]
	b.cursor += count
	return reg, true
}

// GetUleb128 parses an Unsigned LEB128 32-bit integer and advances the cursor.
func (b *BufferSource) GetUleb128() (uint32, bool) {
	rem := b.Remaining()
	lim := min(rem, MaxLeb128Size)
	shiftLim := lim * 7

	var value uint32
	cur := b.cursor
	for shift := 0; shift < shiftLim; shift += 7 {
		byteVal := uint32(b.data[cur])
		cur++
		if shift == 28 && byteVal&0xF0 != 0 {
			return 0, false
		}
		value |= (byteVal & 0x7F) << shift
		if (byteVal & 0x80) == 0 {
			b.cursor = cur
			return value, true
		}
	}
	return 0, false
}

// GetSleb128 parses a Signed LEB128 32-bit integer and advances the cursor.
func (b *BufferSource) GetSleb128() (int32, bool) {
	rem := b.Remaining()
	lim := min(rem, MaxLeb128Size)
	shiftLim := lim * 7

	var value int32
	cur := b.cursor
	for shift := 0; shift < shiftLim; shift += 7 {
		byteVal := b.data[cur]
		cur++
		if shift == 28 && byteVal&0x78 != 0 && byteVal&0x78 != 0x78 {
			return 0, false
		}
		value |= int32(byteVal&0x7F) << shift
		if (byteVal & 0x80) == 0 {
			if shift != 28 {
				value = signExtend32(shift+6, value)
			}
			b.cursor = cur
			return value, true
		}
	}
	return 0, false
}

// SkipLeb128 skips over a LEB128 value without decoding its full integer.
func (b *BufferSource) SkipLeb128() bool {
	rem := b.Remaining()
	lim := min(rem, MaxLeb128Size)
	cur := b.cursor
	for range lim {
		byteVal := b.data[cur]
		cur++
		if (byteVal & 0x80) == 0 {
			b.cursor = cur
			return true
		}
	}
	return false
}

func signExtend32(pos int, v int32) int32 {
	shift := 31 - pos
	return (v << shift) >> shift
}
