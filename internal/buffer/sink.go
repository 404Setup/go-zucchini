package buffer

import (
	"encoding/binary"
	"io"
)

// Sink is the sequential output contract used by patch serialization.
// Implementations may target a fixed buffer or an io.Writer.
type Sink interface {
	PutUint8(uint8) bool
	PutUint16LE(uint16) bool
	PutUint32LE(uint32) bool
	PutUint64LE(uint64) bool
	PutInt32LE(int32) bool
	PutRange([]byte) bool
	PutUleb128(uint32) bool
	PutSleb128(int32) bool
}

// BufferSink acts like an output stream with convenience methods to serialize
// data into a contiguous byte slice. It tracks a write cursor.
type BufferSink struct {
	data   []byte
	cursor int
}

// NewBufferSink creates a new BufferSink wrapping data.
func NewBufferSink(data []byte) *BufferSink {
	return &BufferSink{data: data, cursor: 0}
}

// Remaining returns the number of writeable bytes remaining.
func (b *BufferSink) Remaining() int {
	return len(b.data) - b.cursor
}

// Bytes returns the written portion of the buffer.
func (b *BufferSink) Bytes() []byte {
	return b.data[:b.cursor]
}

// Cursor returns current write position.
func (b *BufferSink) Cursor() int {
	return b.cursor
}

// PutUint8 writes a 1-byte unsigned int.
func (b *BufferSink) PutUint8(v uint8) bool {
	if b.Remaining() < 1 {
		return false
	}
	b.data[b.cursor] = v
	b.cursor++
	return true
}

// PutUint16LE writes a 2-byte little-endian unsigned int.
func (b *BufferSink) PutUint16LE(v uint16) bool {
	if b.Remaining() < 2 {
		return false
	}
	binary.LittleEndian.PutUint16(b.data[b.cursor:], v)
	b.cursor += 2
	return true
}

// PutUint32LE writes a 4-byte little-endian unsigned int.
func (b *BufferSink) PutUint32LE(v uint32) bool {
	if b.Remaining() < 4 {
		return false
	}
	binary.LittleEndian.PutUint32(b.data[b.cursor:], v)
	b.cursor += 4
	return true
}

// PutUint64LE writes an 8-byte little-endian unsigned int.
func (b *BufferSink) PutUint64LE(v uint64) bool {
	if b.Remaining() < 8 {
		return false
	}
	binary.LittleEndian.PutUint64(b.data[b.cursor:], v)
	b.cursor += 8
	return true
}

// PutInt32LE writes a 4-byte little-endian signed int.
func (b *BufferSink) PutInt32LE(v int32) bool {
	return b.PutUint32LE(uint32(v))
}

// PutRange writes a slice of bytes starting at current cursor.
func (b *BufferSink) PutRange(src []byte) bool {
	if b.Remaining() < len(src) {
		return false
	}
	copy(b.data[b.cursor:], src)
	b.cursor += len(src)
	return true
}

// PutUleb128 encodes and writes an Unsigned LEB128 32-bit integer.
func (b *BufferSink) PutUleb128(value uint32) bool {
	var buf [5]byte
	i := 0
	for {
		bVal := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			bVal |= 0x80
			buf[i] = bVal
			i++
		} else {
			buf[i] = bVal
			i++
			break
		}
	}
	return b.PutRange(buf[:i])
}

// PutSleb128 encodes and writes a Signed LEB128 32-bit integer.
func (b *BufferSink) PutSleb128(value int32) bool {
	var buf [5]byte
	i := 0
	more := true
	for more {
		bVal := byte(value & 0x7f)
		value >>= 7
		if (value == 0 && (bVal&0x40) == 0) || (value == -1 && (bVal&0x40) != 0) {
			more = false
		} else {
			bVal |= 0x80
		}
		buf[i] = bVal
		i++
	}
	return b.PutRange(buf[:i])
}

// WriterSink serializes sequentially to an io.Writer and retains the first
// write error. A false return from any Put method is diagnosable through Err.
type WriterSink struct {
	w      io.Writer
	cursor int64
	err    error
}

func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{w: w}
}

func (s *WriterSink) Cursor() int64 { return s.cursor }

func (s *WriterSink) Err() error { return s.err }

func (s *WriterSink) PutUint8(v uint8) bool {
	return s.PutRange([]byte{v})
}

func (s *WriterSink) PutUint16LE(v uint16) bool {
	var data [2]byte
	binary.LittleEndian.PutUint16(data[:], v)
	return s.PutRange(data[:])
}

func (s *WriterSink) PutUint32LE(v uint32) bool {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], v)
	return s.PutRange(data[:])
}

func (s *WriterSink) PutUint64LE(v uint64) bool {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], v)
	return s.PutRange(data[:])
}

func (s *WriterSink) PutInt32LE(v int32) bool {
	return s.PutUint32LE(uint32(v))
}

func (s *WriterSink) PutRange(data []byte) bool {
	if s.err != nil {
		return false
	}
	for len(data) > 0 {
		n, err := s.w.Write(data)
		if err != nil {
			s.err = err
			return false
		}
		if n <= 0 || n > len(data) {
			s.err = io.ErrShortWrite
			return false
		}
		s.cursor += int64(n)
		data = data[n:]
	}
	return true
}

func (s *WriterSink) PutUleb128(value uint32) bool {
	var data [5]byte
	i := 0
	for {
		encoded := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			encoded |= 0x80
		}
		data[i] = encoded
		i++
		if value == 0 {
			return s.PutRange(data[:i])
		}
	}
}

func (s *WriterSink) PutSleb128(value int32) bool {
	var data [5]byte
	i := 0
	for {
		encoded := byte(value & 0x7f)
		value >>= 7
		done := (value == 0 && encoded&0x40 == 0) || (value == -1 && encoded&0x40 != 0)
		if !done {
			encoded |= 0x80
		}
		data[i] = encoded
		i++
		if done {
			return s.PutRange(data[:i])
		}
	}
}
