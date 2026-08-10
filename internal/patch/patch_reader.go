package patch

import (
	"hash/crc32"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/types"
)

type EquivalenceSource struct {
	srcSkip   *buffer.BufferSource
	dstSkip   *buffer.BufferSource
	copyCount *buffer.BufferSource
	prevSrc   types.Offset
	prevDst   types.Offset
	failed    bool
}

func NewEquivalenceSource() *EquivalenceSource {
	return &EquivalenceSource{
		srcSkip:   buffer.NewBufferSource(nil),
		dstSkip:   buffer.NewBufferSource(nil),
		copyCount: buffer.NewBufferSource(nil),
	}
}

func (s *EquivalenceSource) Initialize(source *buffer.BufferSource) bool {
	b1, ok1 := ParseBuffer(source)
	b2, ok2 := ParseBuffer(source)
	b3, ok3 := ParseBuffer(source)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	s.srcSkip = buffer.NewBufferSource(b1)
	s.dstSkip = buffer.NewBufferSource(b2)
	s.copyCount = buffer.NewBufferSource(b3)
	s.prevSrc = 0
	s.prevDst = 0
	s.failed = false
	return true
}

func (s *EquivalenceSource) GetNext() (types.Equivalence, bool) {
	if s.srcSkip.Remaining() == 0 || s.dstSkip.Remaining() == 0 || s.copyCount.Remaining() == 0 {
		return types.Equivalence{}, false
	}

	count, ok1 := DecodeVarUInt(s.copyCount)
	srcSkip, ok2 := DecodeVarInt(s.srcSkip)
	dstSkip, ok3 := DecodeVarUInt(s.dstSkip)
	if !ok1 || !ok2 || !ok3 {
		s.failed = true
		return types.Equivalence{}, false
	}

	srcValue := int64(s.prevSrc) + int64(srcSkip)
	if srcValue < 0 || srcValue > int64(^uint32(0)) {
		s.failed = true
		return types.Equivalence{}, false
	}
	srcOffset := types.Offset(srcValue)
	dstValue := uint64(s.prevDst) + uint64(dstSkip)
	if dstValue > uint64(^uint32(0)) {
		s.failed = true
		return types.Equivalence{}, false
	}
	dstOffset := types.Offset(dstValue)
	length := types.Offset(count)
	if uint64(srcOffset)+uint64(length) > uint64(^uint32(0)) ||
		uint64(dstOffset)+uint64(length) > uint64(^uint32(0)) {
		s.failed = true
		return types.Equivalence{}, false
	}

	s.prevSrc = srcOffset + length
	s.prevDst = dstOffset + length

	return types.Equivalence{
		SrcOffset: srcOffset,
		DstOffset: dstOffset,
		Length:    length,
	}, true
}

func (s *EquivalenceSource) Done() bool {
	return !s.failed && s.srcSkip.Remaining() == 0 && s.dstSkip.Remaining() == 0 && s.copyCount.Remaining() == 0
}

type ExtraDataSource struct {
	extraData *buffer.BufferSource
}

func NewExtraDataSource() *ExtraDataSource {
	return &ExtraDataSource{extraData: buffer.NewBufferSource(nil)}
}

func (s *ExtraDataSource) Initialize(source *buffer.BufferSource) bool {
	b, ok := ParseBuffer(source)
	if !ok {
		return false
	}
	s.extraData = buffer.NewBufferSource(b)
	return true
}

func (s *ExtraDataSource) GetNext(size types.Offset) ([]byte, bool) {
	return s.extraData.GetRegion(int(size))
}

func (s *ExtraDataSource) Done() bool {
	return s.extraData.Remaining() == 0
}

type RawDeltaSource struct {
	rawDeltaSkip *buffer.BufferSource
	rawDeltaDiff *buffer.BufferSource
	compensation types.Offset
	failed       bool
}

func NewRawDeltaSource() *RawDeltaSource {
	return &RawDeltaSource{
		rawDeltaSkip: buffer.NewBufferSource(nil),
		rawDeltaDiff: buffer.NewBufferSource(nil),
	}
}

func (s *RawDeltaSource) Initialize(source *buffer.BufferSource) bool {
	b1, ok1 := ParseBuffer(source)
	b2, ok2 := ParseBuffer(source)
	if !ok1 || !ok2 {
		return false
	}
	s.rawDeltaSkip = buffer.NewBufferSource(b1)
	s.rawDeltaDiff = buffer.NewBufferSource(b2)
	s.compensation = 0
	s.failed = false
	return true
}

func (s *RawDeltaSource) GetNext() (RawDeltaUnit, bool) {
	if s.rawDeltaSkip.Remaining() == 0 || s.rawDeltaDiff.Remaining() == 0 {
		return RawDeltaUnit{}, false
	}
	skip, ok1 := DecodeVarUInt(s.rawDeltaSkip)
	diffByte, ok2 := s.rawDeltaDiff.GetUint8()
	if !ok1 || !ok2 {
		s.failed = true
		return RawDeltaUnit{}, false
	}
	copyOffsetValue := uint64(s.compensation) + uint64(skip)
	if copyOffsetValue > uint64(^uint32(0)) || diffByte == 0 {
		s.failed = true
		return RawDeltaUnit{}, false
	}
	copyOffset := types.Offset(copyOffsetValue)
	if copyOffset == types.Offset(^uint32(0)) {
		s.failed = true
		return RawDeltaUnit{}, false
	}
	s.compensation = copyOffset + 1
	return RawDeltaUnit{CopyOffset: copyOffset, Diff: int8(diffByte)}, true
}

func (s *RawDeltaSource) Done() bool {
	return !s.failed && s.rawDeltaSkip.Remaining() == 0 && s.rawDeltaDiff.Remaining() == 0
}

type ReferenceDeltaSource struct {
	source *buffer.BufferSource
	failed bool
}

func NewReferenceDeltaSource() *ReferenceDeltaSource {
	return &ReferenceDeltaSource{source: buffer.NewBufferSource(nil)}
}

func (s *ReferenceDeltaSource) Initialize(source *buffer.BufferSource) bool {
	b, ok := ParseBuffer(source)
	if !ok {
		return false
	}
	s.source = buffer.NewBufferSource(b)
	s.failed = false
	return true
}

func (s *ReferenceDeltaSource) GetNext() (int32, bool) {
	if s.source.Remaining() == 0 {
		return 0, false
	}
	val, ok := DecodeVarInt(s.source)
	if !ok {
		s.failed = true
		return 0, false
	}
	return val, true
}

func (s *ReferenceDeltaSource) Done() bool {
	return !s.failed && s.source.Remaining() == 0
}

type TargetSource struct {
	extraTargets *buffer.BufferSource
	compensation types.Offset
	failed       bool
}

func NewTargetSource() *TargetSource {
	return &TargetSource{
		extraTargets: buffer.NewBufferSource(nil),
	}
}

func (s *TargetSource) Initialize(source *buffer.BufferSource) bool {
	b, ok := ParseBuffer(source)
	if !ok {
		return false
	}
	s.extraTargets = buffer.NewBufferSource(b)
	s.compensation = 0
	s.failed = false
	return true
}

func (s *TargetSource) GetNext() (types.Offset, bool) {
	if s.extraTargets.Remaining() == 0 {
		return 0, false
	}
	diff, ok := DecodeVarUInt(s.extraTargets)
	if !ok {
		s.failed = true
		return 0, false
	}
	targetValue := uint64(s.compensation) + uint64(diff)
	if targetValue > uint64(^uint32(0)) {
		s.failed = true
		return 0, false
	}
	target := types.Offset(targetValue)
	if target == types.Offset(^uint32(0)) {
		s.failed = true
		return 0, false
	}
	s.compensation = target + 1
	return target, true
}

func (s *TargetSource) Done() bool {
	return !s.failed && s.extraTargets.Remaining() == 0
}

type PatchElementReader struct {
	elementMatch   types.ElementMatch
	bufEquiv       []byte
	bufExtra       []byte
	bufRawDelta    []byte
	bufRefDelta    []byte
	bufExtraTarget map[types.PoolTag][]byte
}

func NewPatchElementReader() *PatchElementReader {
	return &PatchElementReader{}
}

func (r *PatchElementReader) Initialize(source *buffer.BufferSource) bool {
	hdr, ok := ParsePatchElementHeader(source)
	if !ok || hdr.Version != 1 || hdr.OldLength == 0 || hdr.NewLength == 0 ||
		!isSupportedExecutableType(types.ExecutableType(hdr.ExeType)) ||
		uint64(hdr.OldOffset) > uint64(^uint(0)>>1) ||
		uint64(hdr.OldLength) > uint64(^uint(0)>>1) ||
		uint64(hdr.NewOffset) > uint64(^uint(0)>>1) ||
		uint64(hdr.NewLength) > uint64(^uint(0)>>1) {
		return false
	}
	r.bufExtraTarget = nil

	r.elementMatch = types.ElementMatch{
		OldElement: types.Element{
			Region:  types.BufferRegion{Offset: int(hdr.OldOffset), Size: int(hdr.OldLength)},
			ExeType: types.ExecutableType(hdr.ExeType),
		},
		NewElement: types.Element{
			Region:  types.BufferRegion{Offset: int(hdr.NewOffset), Size: int(hdr.NewLength)},
			ExeType: types.ExecutableType(hdr.ExeType),
		},
	}

	startEquiv := source.Cursor()
	dummyEquiv := NewEquivalenceSource()
	if !dummyEquiv.Initialize(source) {
		return false
	}
	r.bufEquiv = source.RegionFrom(startEquiv)

	startExtra := source.Cursor()
	dummyExtra := NewExtraDataSource()
	if !dummyExtra.Initialize(source) {
		return false
	}
	r.bufExtra = source.RegionFrom(startExtra)
	copied, valid := r.validateEquivalencesAndExtraData()
	if !valid {
		return false
	}

	startRaw := source.Cursor()
	dummyRaw := NewRawDeltaSource()
	if !dummyRaw.Initialize(source) {
		return false
	}
	r.bufRawDelta = source.RegionFrom(startRaw)
	if !r.validateRawDelta(copied) {
		return false
	}

	startRef := source.Cursor()
	dummyRef := NewReferenceDeltaSource()
	if !dummyRef.Initialize(source) {
		return false
	}
	r.bufRefDelta = source.RegionFrom(startRef)
	if !r.validateReferenceDelta() {
		return false
	}

	numPools, ok := source.GetUint32LE()
	if !ok {
		return false
	}
	for i := uint32(0); i < numPools; i++ {
		poolTagVal, ok1 := source.GetUint8()
		if !ok1 {
			return false
		}
		poolTag := types.PoolTag(poolTagVal)
		if poolTag == types.NoPoolTag {
			return false
		}
		if _, exists := r.bufExtraTarget[poolTag]; exists {
			return false
		}
		if r.bufExtraTarget == nil {
			capacity := int(types.NoPoolTag)
			if numPools < uint32(capacity) {
				capacity = int(numPools)
			}
			r.bufExtraTarget = make(map[types.PoolTag][]byte, capacity)
		}
		startTarget := source.Cursor()
		dummyTarget := NewTargetSource()
		if !dummyTarget.Initialize(source) {
			return false
		}
		r.bufExtraTarget[poolTag] = source.RegionFrom(startTarget)
		if !r.validateExtraTargets(poolTag) {
			return false
		}
	}

	return true
}

func isSupportedExecutableType(exeType types.ExecutableType) bool {
	switch exeType {
	case types.ExecutableTypeNoOp,
		types.ExecutableTypeWin32X86,
		types.ExecutableTypeWin32X64,
		types.ExecutableTypeElfX86,
		types.ExecutableTypeElfX64,
		types.ExecutableTypeElfAArch32,
		types.ExecutableTypeElfAArch64:
		return true
	default:
		return false
	}
}

func (r *PatchElementReader) validateEquivalencesAndExtraData() (uint64, bool) {
	equivalences := r.GetEquivalenceSource()
	var copied uint64
	var prevDstEnd types.Offset
	for {
		eq, ok := equivalences.GetNext()
		if !ok {
			break
		}
		if uint64(eq.SrcOffset)+uint64(eq.Length) > uint64(r.elementMatch.OldElement.Region.Size) ||
			uint64(eq.DstOffset)+uint64(eq.Length) > uint64(r.elementMatch.NewElement.Region.Size) ||
			eq.DstOffset < prevDstEnd {
			return 0, false
		}
		copied += uint64(eq.Length)
		if copied > uint64(r.elementMatch.NewElement.Region.Size) {
			return 0, false
		}
		prevDstEnd = eq.DstEnd()
	}
	if !equivalences.Done() {
		return 0, false
	}

	extra := r.GetExtraDataSource()
	expected := r.elementMatch.NewElement.Region.Size - int(copied)
	data, ok := extra.GetNext(types.Offset(expected))
	return copied, ok && len(data) == expected && extra.Done()
}

func (r *PatchElementReader) validateRawDelta(copied uint64) bool {
	source := r.GetRawDeltaSource()
	for {
		delta, ok := source.GetNext()
		if !ok {
			break
		}
		if uint64(delta.CopyOffset) >= copied {
			return false
		}
	}
	return source.Done()
}

func (r *PatchElementReader) validateReferenceDelta() bool {
	source := r.GetReferenceDeltaSource()
	for {
		if _, ok := source.GetNext(); !ok {
			break
		}
	}
	return source.Done()
}

func (r *PatchElementReader) validateExtraTargets(poolTag types.PoolTag) bool {
	source := r.GetExtraTargetSource(poolTag)
	for {
		if _, ok := source.GetNext(); !ok {
			break
		}
	}
	return source.Done()
}

func (r *PatchElementReader) ElementMatch() types.ElementMatch {
	return r.elementMatch
}

func (r *PatchElementReader) GetEquivalenceSource() *EquivalenceSource {
	s := NewEquivalenceSource()
	s.Initialize(buffer.NewBufferSource(r.bufEquiv))
	return s
}

func (r *PatchElementReader) GetExtraDataSource() *ExtraDataSource {
	s := NewExtraDataSource()
	s.Initialize(buffer.NewBufferSource(r.bufExtra))
	return s
}

func (r *PatchElementReader) GetRawDeltaSource() *RawDeltaSource {
	s := NewRawDeltaSource()
	s.Initialize(buffer.NewBufferSource(r.bufRawDelta))
	return s
}

func (r *PatchElementReader) GetReferenceDeltaSource() *ReferenceDeltaSource {
	s := NewReferenceDeltaSource()
	s.Initialize(buffer.NewBufferSource(r.bufRefDelta))
	return s
}

func (r *PatchElementReader) GetExtraTargetSource(pool types.PoolTag) *TargetSource {
	s := NewTargetSource()
	if b, ok := r.bufExtraTarget[pool]; ok {
		s.Initialize(buffer.NewBufferSource(b))
	}
	return s
}

func (r *PatchElementReader) BufEquivLen() int    { return len(r.bufEquiv) }
func (r *PatchElementReader) BufExtraLen() int    { return len(r.bufExtra) }
func (r *PatchElementReader) BufRawDeltaLen() int { return len(r.bufRawDelta) }
func (r *PatchElementReader) BufRefDeltaLen() int { return len(r.bufRefDelta) }
func (r *PatchElementReader) ExtraTargetLens() map[types.PoolTag]int {
	m := make(map[types.PoolTag]int)
	for k, v := range r.bufExtraTarget {
		m[k] = len(v)
	}
	return m
}

type EnsemblePatchReader struct {
	header   PatchHeader
	elements []PatchElementReader
}

func CreateEnsemblePatchReader(buf []byte) (*EnsemblePatchReader, bool) {
	reader := &EnsemblePatchReader{}
	source := buffer.NewBufferSource(buf)
	if !reader.Initialize(source) {
		return nil, false
	}
	return reader, true
}

func (r *EnsemblePatchReader) Initialize(source *buffer.BufferSource) bool {
	hdr, ok := ParsePatchHeader(source)
	if !ok || hdr.Magic != PatchHeaderMagic || hdr.MajorVersion != 2 ||
		uint64(hdr.OldSize) > uint64(^uint(0)>>1) ||
		uint64(hdr.NewSize) > uint64(^uint(0)>>1) {
		return false
	}
	r.header = *hdr
	r.elements = nil

	numElements, ok := source.GetUint32LE()
	if !ok {
		return false
	}

	var currentDstOffset uint64
	for i := uint32(0); i < numElements; i++ {
		elemReader := NewPatchElementReader()
		if !elemReader.Initialize(source) {
			return false
		}
		match := elemReader.ElementMatch()
		oldRegion := match.OldElement.Region
		newRegion := match.NewElement.Region
		if uint64(oldRegion.Offset)+uint64(oldRegion.Size) > uint64(hdr.OldSize) ||
			uint64(newRegion.Offset)+uint64(newRegion.Size) > uint64(hdr.NewSize) ||
			uint64(newRegion.Offset) != currentDstOffset {
			return false
		}
		currentDstOffset += uint64(newRegion.Size)
		r.elements = append(r.elements, *elemReader)
	}

	return currentDstOffset == uint64(hdr.NewSize) && source.Remaining() == 0
}

func (r *EnsemblePatchReader) CheckOldFile(oldImage []byte) bool {
	if len(oldImage) != int(r.header.OldSize) {
		return false
	}
	return crc32.ChecksumIEEE(oldImage) == r.header.OldCRC
}

func (r *EnsemblePatchReader) CheckNewFile(newImage []byte) bool {
	if len(newImage) != int(r.header.NewSize) {
		return false
	}
	return crc32.ChecksumIEEE(newImage) == r.header.NewCRC
}

func (r *EnsemblePatchReader) Header() PatchHeader {
	return r.header
}

func (r *EnsemblePatchReader) Elements() []PatchElementReader {
	return r.elements
}
