package disasm

import (
	"github.com/404Setup/go-zucchini/internal/types"
)

type Disassembler interface {
	GetExeType() types.ExecutableType
	GetExeTypeString() string
	Image() []byte
	Size() int
	NumEquivalenceIterations() int
	Parse() bool
	MakeReferenceGroups() []ReferenceGroup
}

type ReferenceGroup struct {
	Traits             types.ReferenceTypeTraits
	ReferenceCountHint int
	ReaderFactory      func(lower, upper types.Offset) types.ReferenceReader
	WriterFactory      func(image []byte) types.ReferenceWriter
	MixerFactory       func(oldImage, newImage []byte) ReferenceMixer
}

type ReferenceMixer interface {
	Mix(srcOffset, dstOffset types.Offset) []byte
}

func (g ReferenceGroup) TypeTag() types.TypeTag {
	return g.Traits.TypeTag
}

func (g ReferenceGroup) PoolTag() types.PoolTag {
	return g.Traits.PoolTag
}

func (g ReferenceGroup) Width() types.Offset {
	return g.Traits.Width
}

func (g ReferenceGroup) GetReader(lower, upper types.Offset) types.ReferenceReader {
	return g.ReaderFactory(lower, upper)
}

func (g ReferenceGroup) GetWriter(image []byte) types.ReferenceWriter {
	return g.WriterFactory(image)
}

func (g ReferenceGroup) GetMixer(oldImage, newImage []byte) ReferenceMixer {
	if g.MixerFactory == nil {
		return nil
	}
	return g.MixerFactory(oldImage, newImage)
}

type referenceGroupsForWriter interface {
	MakeReferenceGroupsForWriter() []ReferenceGroup
}

// MakeReferenceGroupsForWriter avoids reference discovery when a caller only
// needs correction writers. Disassemblers without a specialized path retain
// the regular behavior.
func MakeReferenceGroupsForWriter(d Disassembler) []ReferenceGroup {
	if writerGroups, ok := d.(referenceGroupsForWriter); ok {
		return writerGroups.MakeReferenceGroupsForWriter()
	}
	return d.MakeReferenceGroups()
}

type EmptyReferenceReader struct{}

func NewEmptyReferenceReader() *EmptyReferenceReader {
	return &EmptyReferenceReader{}
}

func (r *EmptyReferenceReader) GetNext() (types.Reference, bool) {
	return types.Reference{}, false
}

type EmptyReferenceWriter struct{}

func NewEmptyReferenceWriter() *EmptyReferenceWriter {
	return &EmptyReferenceWriter{}
}

func (w *EmptyReferenceWriter) PutNext(ref types.Reference) {}
