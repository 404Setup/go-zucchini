package patch

import (
	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/types"
)

const PatchHeaderMagic uint32 = 'Z' | ('u' << 8) | ('c' << 16) | ('c' << 24)

type PatchHeader struct {
	Magic        uint32
	MajorVersion uint16
	MinorVersion uint16
	OldSize      uint32
	OldCRC       uint32
	NewSize      uint32
	NewCRC       uint32
}

func (h *PatchHeader) WriteTo(sink buffer.Sink) bool {
	return sink.PutUint32LE(h.Magic) &&
		sink.PutUint16LE(h.MajorVersion) &&
		sink.PutUint16LE(h.MinorVersion) &&
		sink.PutUint32LE(h.OldSize) &&
		sink.PutUint32LE(h.OldCRC) &&
		sink.PutUint32LE(h.NewSize) &&
		sink.PutUint32LE(h.NewCRC)
}

func ParsePatchHeader(source *buffer.BufferSource) (*PatchHeader, bool) {
	if source.Remaining() < 24 {
		return nil, false
	}
	magic, _ := source.GetUint32LE()
	major, _ := source.GetUint16LE()
	minor, _ := source.GetUint16LE()
	oldSize, _ := source.GetUint32LE()
	oldCRC, _ := source.GetUint32LE()
	newSize, _ := source.GetUint32LE()
	newCRC, _ := source.GetUint32LE()

	return &PatchHeader{
		Magic:        magic,
		MajorVersion: major,
		MinorVersion: minor,
		OldSize:      oldSize,
		OldCRC:       oldCRC,
		NewSize:      newSize,
		NewCRC:       newCRC,
	}, true
}

type PatchElementHeader struct {
	OldOffset uint32
	OldLength uint32
	NewOffset uint32
	NewLength uint32
	ExeType   uint32
	Version   uint16
}

func (h *PatchElementHeader) WriteTo(sink buffer.Sink) bool {
	return sink.PutUint32LE(h.OldOffset) &&
		sink.PutUint32LE(h.OldLength) &&
		sink.PutUint32LE(h.NewOffset) &&
		sink.PutUint32LE(h.NewLength) &&
		sink.PutUint32LE(h.ExeType) &&
		sink.PutUint16LE(h.Version)
}

func ParsePatchElementHeader(source *buffer.BufferSource) (*PatchElementHeader, bool) {
	if source.Remaining() < 22 {
		return nil, false
	}
	oldOffset, _ := source.GetUint32LE()
	oldLength, _ := source.GetUint32LE()
	newOffset, _ := source.GetUint32LE()
	newLength, _ := source.GetUint32LE()
	exeType, _ := source.GetUint32LE()
	version, _ := source.GetUint16LE()

	return &PatchElementHeader{
		OldOffset: oldOffset,
		OldLength: oldLength,
		NewOffset: newOffset,
		NewLength: newLength,
		ExeType:   exeType,
		Version:   version,
	}, true
}

type RawDeltaUnit struct {
	CopyOffset types.Offset
	Diff       int8
}

func EncodeVarUInt(value uint64) []byte {
	return AppendVarUInt(nil, value)
}

func AppendVarUInt(buf []byte, value uint64) []byte {
	for value >= 0x80 {
		buf = append(buf, byte(value)|0x80)
		value >>= 7
	}
	buf = append(buf, byte(value))
	return buf
}

func EncodeVarInt(value int64) []byte {
	return AppendVarInt(nil, value)
}

func AppendVarInt(buf []byte, value int64) []byte {
	if value < 0 {
		return AppendVarUInt(buf, (uint64(^value)<<1)|1)
	}
	return AppendVarUInt(buf, uint64(value)<<1)
}

func DecodeVarUInt(source *buffer.BufferSource) (uint32, bool) {
	var val uint32
	for shift := uint(0); shift < 32; shift += 7 {
		b, ok := source.GetUint8()
		if !ok {
			return 0, false
		}
		if shift == 28 && b&0xF0 != 0 {
			return 0, false
		}
		val |= uint32(b&0x7F) << shift
		if (b & 0x80) == 0 {
			return val, true
		}
	}
	return 0, false
}

func DecodeVarInt(source *buffer.BufferSource) (int32, bool) {
	uVal, ok := DecodeVarUInt(source)
	if !ok {
		return 0, false
	}
	if (uVal & 1) != 0 {
		return ^int32(uVal >> 1), true
	}
	return int32(uVal >> 1), true
}

func SerializeBuffer(data []byte, sink buffer.Sink) bool {
	if !sink.PutUint32LE(uint32(len(data))) {
		return false
	}
	return sink.PutRange(data)
}

func SerializedBufferSize(data []byte) int {
	return 4 + len(data)
}

func ParseBuffer(source *buffer.BufferSource) ([]byte, bool) {
	sz, ok := source.GetUint32LE()
	if !ok || uint64(sz) > uint64(^uint(0)>>1) {
		return nil, false
	}
	return source.GetRegion(int(sz))
}
