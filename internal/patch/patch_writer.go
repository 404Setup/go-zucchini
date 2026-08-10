package patch

import (
	"hash/crc32"
	"sort"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/types"
)

type EquivalenceSink struct {
	srcSkip   []byte
	dstSkip   []byte
	copyCount []byte
	prevSrc   types.Offset
	prevDst   types.Offset
}

func NewEquivalenceSink() *EquivalenceSink {
	return &EquivalenceSink{}
}

func (s *EquivalenceSink) PutNext(eq types.Equivalence) {
	srcSkip := int32(uint32(eq.SrcOffset) - uint32(s.prevSrc))
	dstSkip := uint64(eq.DstOffset - s.prevDst)
	count := uint64(eq.Length)

	s.srcSkip = AppendVarInt(s.srcSkip, int64(srcSkip))
	s.dstSkip = AppendVarUInt(s.dstSkip, dstSkip)
	s.copyCount = AppendVarUInt(s.copyCount, count)

	s.prevSrc = eq.SrcOffset + eq.Length
	s.prevDst = eq.DstOffset + eq.Length
}

func (s *EquivalenceSink) SerializedSize() int {
	return SerializedBufferSize(s.srcSkip) + SerializedBufferSize(s.dstSkip) + SerializedBufferSize(s.copyCount)
}

func (s *EquivalenceSink) SerializeInto(sink buffer.Sink) bool {
	return SerializeBuffer(s.srcSkip, sink) &&
		SerializeBuffer(s.dstSkip, sink) &&
		SerializeBuffer(s.copyCount, sink)
}

type ExtraDataSink struct {
	image   []byte
	regions []extraDataRegion
	size    int
}

type extraDataRegion struct {
	offset uint32
	length uint32
}

func NewExtraDataSink(image []byte) *ExtraDataSink {
	return &ExtraDataSink{image: image}
}

func (s *ExtraDataSink) PutRegion(offset, length int) bool {
	if offset < 0 || length < 0 || offset > len(s.image)-length {
		return false
	}
	if length > 0 {
		s.regions = append(s.regions, extraDataRegion{offset: uint32(offset), length: uint32(length)})
		s.size += length
	}
	return true
}

func (s *ExtraDataSink) SerializedSize() int {
	return 4 + s.size
}

func (s *ExtraDataSink) SerializeInto(sink buffer.Sink) bool {
	if !sink.PutUint32LE(uint32(s.size)) {
		return false
	}
	for _, region := range s.regions {
		lo := int(region.offset)
		hi := lo + int(region.length)
		if !sink.PutRange(s.image[lo:hi]) {
			return false
		}
	}
	return true
}

type RawDeltaSink struct {
	rawDeltaSkip []byte
	rawDeltaDiff []byte
	compensation types.Offset
}

func NewRawDeltaSink() *RawDeltaSink {
	return &RawDeltaSink{}
}

func (s *RawDeltaSink) PutNext(delta RawDeltaUnit) {
	skip := uint64(delta.CopyOffset - s.compensation)
	s.rawDeltaSkip = AppendVarUInt(s.rawDeltaSkip, skip)
	s.rawDeltaDiff = append(s.rawDeltaDiff, byte(delta.Diff))
	s.compensation = delta.CopyOffset + 1
}

func (s *RawDeltaSink) SerializedSize() int {
	return SerializedBufferSize(s.rawDeltaSkip) + SerializedBufferSize(s.rawDeltaDiff)
}

func (s *RawDeltaSink) SerializeInto(sink buffer.Sink) bool {
	return SerializeBuffer(s.rawDeltaSkip, sink) && SerializeBuffer(s.rawDeltaDiff, sink)
}

type ReferenceDeltaSink struct {
	referenceDelta []byte
}

func NewReferenceDeltaSink() *ReferenceDeltaSink {
	return &ReferenceDeltaSink{}
}

func (s *ReferenceDeltaSink) PutNext(diff int32) {
	s.referenceDelta = AppendVarInt(s.referenceDelta, int64(diff))
}

func (s *ReferenceDeltaSink) SerializedSize() int {
	return SerializedBufferSize(s.referenceDelta)
}

func (s *ReferenceDeltaSink) SerializeInto(sink buffer.Sink) bool {
	return SerializeBuffer(s.referenceDelta, sink)
}

type TargetSink struct {
	extraTargets []byte
	compensation types.Offset
}

func NewTargetSink() *TargetSink {
	return &TargetSink{}
}

func (s *TargetSink) PutNext(target types.Offset) {
	diff := uint64(target - s.compensation)
	s.extraTargets = AppendVarUInt(s.extraTargets, diff)
	s.compensation = target + 1
}

func (s *TargetSink) SerializedSize() int {
	return SerializedBufferSize(s.extraTargets)
}

func (s *TargetSink) SerializeInto(sink buffer.Sink) bool {
	return SerializeBuffer(s.extraTargets, sink)
}

type PatchElementWriter struct {
	elementMatch   types.ElementMatch
	equivalences   *EquivalenceSink
	extraData      *ExtraDataSink
	rawDelta       *RawDeltaSink
	referenceDelta *ReferenceDeltaSink
	extraTargets   map[types.PoolTag]*TargetSink
}

func NewPatchElementWriter(match types.ElementMatch) *PatchElementWriter {
	return &PatchElementWriter{
		elementMatch: match,
		extraTargets: make(map[types.PoolTag]*TargetSink),
	}
}

func (w *PatchElementWriter) SetEquivalenceSink(eq *EquivalenceSink) {
	w.equivalences = eq
}

func (w *PatchElementWriter) SetExtraDataSink(ed *ExtraDataSink) {
	w.extraData = ed
}

func (w *PatchElementWriter) SetRawDeltaSink(rd *RawDeltaSink) {
	w.rawDelta = rd
}

func (w *PatchElementWriter) SetReferenceDeltaSink(rd *ReferenceDeltaSink) {
	w.referenceDelta = rd
}

func (w *PatchElementWriter) SetTargetSink(pool types.PoolTag, ts *TargetSink) {
	w.extraTargets[pool] = ts
}

func (w *PatchElementWriter) SerializedSize() int {
	size := 22
	if w.equivalences != nil {
		size += w.equivalences.SerializedSize()
	} else {
		size += NewEquivalenceSink().SerializedSize()
	}
	if w.extraData != nil {
		size += w.extraData.SerializedSize()
	} else {
		size += NewExtraDataSink(nil).SerializedSize()
	}
	if w.rawDelta != nil {
		size += w.rawDelta.SerializedSize()
	} else {
		size += NewRawDeltaSink().SerializedSize()
	}
	if w.referenceDelta != nil {
		size += w.referenceDelta.SerializedSize()
	} else {
		size += NewReferenceDeltaSink().SerializedSize()
	}

	size += 4

	for _, ts := range w.extraTargets {
		size += 1 + ts.SerializedSize()
	}

	return size
}

func (w *PatchElementWriter) SerializeInto(sink buffer.Sink) bool {
	hdr := PatchElementHeader{
		OldOffset: uint32(w.elementMatch.OldElement.Region.Offset),
		OldLength: uint32(w.elementMatch.OldElement.Region.Size),
		NewOffset: uint32(w.elementMatch.NewElement.Region.Offset),
		NewLength: uint32(w.elementMatch.NewElement.Region.Size),
		ExeType:   uint32(w.elementMatch.OldElement.ExeType),
		Version:   1,
	}
	if !hdr.WriteTo(sink) {
		return false
	}

	eq := w.equivalences
	if eq == nil {
		eq = NewEquivalenceSink()
	}
	if !eq.SerializeInto(sink) {
		return false
	}

	ed := w.extraData
	if ed == nil {
		ed = NewExtraDataSink(nil)
	}
	if !ed.SerializeInto(sink) {
		return false
	}

	rd := w.rawDelta
	if rd == nil {
		rd = NewRawDeltaSink()
	}
	if !rd.SerializeInto(sink) {
		return false
	}

	refD := w.referenceDelta
	if refD == nil {
		refD = NewReferenceDeltaSink()
	}
	if !refD.SerializeInto(sink) {
		return false
	}

	if !sink.PutUint32LE(uint32(len(w.extraTargets))) {
		return false
	}

	tags := make([]types.PoolTag, 0, len(w.extraTargets))
	for tag := range w.extraTargets {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })

	for _, tag := range tags {
		ts := w.extraTargets[tag]
		if !sink.PutUint8(byte(tag)) || !ts.SerializeInto(sink) {
			return false
		}
	}

	return true
}

type EnsemblePatchWriter struct {
	header   PatchHeader
	elements []PatchElementWriter
}

func NewEnsemblePatchWriter(oldImage, newImage []byte) *EnsemblePatchWriter {
	return &EnsemblePatchWriter{
		header: PatchHeader{
			Magic:        PatchHeaderMagic,
			MajorVersion: 2,
			MinorVersion: 0,
			OldSize:      uint32(len(oldImage)),
			OldCRC:       crc32.ChecksumIEEE(oldImage),
			NewSize:      uint32(len(newImage)),
			NewCRC:       crc32.ChecksumIEEE(newImage),
		},
	}
}

func (w *EnsemblePatchWriter) AddElement(elem PatchElementWriter) {
	w.elements = append(w.elements, elem)
}

func (w *EnsemblePatchWriter) SerializedSize() int {
	size := 24 + 4

	for _, elem := range w.elements {
		size += elem.SerializedSize()
	}

	return size
}

func (w *EnsemblePatchWriter) SerializeInto(sink buffer.Sink) bool {
	if !w.header.WriteTo(sink) {
		return false
	}
	if !sink.PutUint32LE(uint32(len(w.elements))) {
		return false
	}
	for _, elem := range w.elements {
		if !elem.SerializeInto(sink) {
			return false
		}
	}
	return true
}
