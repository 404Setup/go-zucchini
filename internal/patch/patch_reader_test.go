package patch

import (
	"encoding/binary"
	"testing"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/types"
)

func makeValidTestPatch(t *testing.T) []byte {
	t.Helper()
	oldImage := []byte("abc")
	newImage := []byte("axc")
	match := types.ElementMatch{
		OldElement: types.Element{Region: types.BufferRegion{Size: len(oldImage)}, ExeType: types.ExecutableTypeNoOp},
		NewElement: types.Element{Region: types.BufferRegion{Size: len(newImage)}, ExeType: types.ExecutableTypeNoOp},
	}
	elem := NewPatchElementWriter(match)
	equivalences := NewEquivalenceSink()
	equivalences.PutNext(types.Equivalence{Length: 3})
	elem.SetEquivalenceSink(equivalences)
	elem.SetExtraDataSink(NewExtraDataSink(nil))
	rawDelta := NewRawDeltaSink()
	rawDelta.PutNext(RawDeltaUnit{CopyOffset: 1, Diff: int8('x' - 'b')})
	elem.SetRawDeltaSink(rawDelta)
	elem.SetReferenceDeltaSink(NewReferenceDeltaSink())

	writer := NewEnsemblePatchWriter(oldImage, newImage)
	writer.AddElement(*elem)
	data := make([]byte, writer.SerializedSize())
	if !writer.SerializeInto(buffer.NewBufferSink(data)) {
		t.Fatal("SerializeInto failed")
	}
	return data
}

func TestEnsemblePatchReaderValidation(t *testing.T) {
	valid := makeValidTestPatch(t)
	if _, ok := CreateEnsemblePatchReader(valid); !ok {
		t.Fatal("valid patch rejected")
	}

	tests := map[string]func([]byte) []byte{
		"major version": func(p []byte) []byte {
			binary.LittleEndian.PutUint16(p[4:], 3)
			return p
		},
		"unknown executable": func(p []byte) []byte {
			binary.LittleEndian.PutUint32(p[44:], uint32(types.ExecutableTypeUnknown))
			return p
		},
		"element version": func(p []byte) []byte {
			binary.LittleEndian.PutUint16(p[48:], 2)
			return p
		},
		"empty old element": func(p []byte) []byte {
			binary.LittleEndian.PutUint32(p[32:], 0)
			return p
		},
		"noncontiguous new element": func(p []byte) []byte {
			binary.LittleEndian.PutUint32(p[36:], 1)
			return p
		},
		"equivalence out of bounds": func(p []byte) []byte {
			p[64] = 4
			return p
		},
		"raw delta out of bounds": func(p []byte) []byte {
			p[73] = 3
			return p
		},
		"trailing bytes": func(p []byte) []byte {
			return append(p, 0)
		},
		"invalid pool tag": func(p []byte) []byte {
			binary.LittleEndian.PutUint32(p[len(p)-4:], 1)
			return append(p, byte(types.NoPoolTag), 0, 0, 0, 0)
		},
		"extra target overflow": func(p []byte) []byte {
			binary.LittleEndian.PutUint32(p[len(p)-4:], 1)
			return append(p, 0, 5, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			patchBytes := append([]byte(nil), valid...)
			if _, ok := CreateEnsemblePatchReader(mutate(patchBytes)); ok {
				t.Fatal("invalid patch accepted")
			}
		})
	}
}

func TestEnsemblePatchReaderAcceptsSyntheticExtraTarget(t *testing.T) {
	patchBytes := makeValidTestPatch(t)
	binary.LittleEndian.PutUint32(patchBytes[len(patchBytes)-4:], 1)
	// Target 3 is immediately beyond this element's three file bytes, but it is
	// a valid synthetic offset for a PE RVA in a section's virtual-only tail.
	patchBytes = append(patchBytes, 0, 1, 0, 0, 0, 3)
	if _, ok := CreateEnsemblePatchReader(patchBytes); !ok {
		t.Fatal("valid synthetic extra target was rejected")
	}
}

func TestSourcesRejectInvalidEncodedValues(t *testing.T) {
	if _, ok := DecodeVarUInt(buffer.NewBufferSource([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x1F})); ok {
		t.Fatal("overflowing uint32 varint was accepted")
	}

	rawData := []byte{1, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	raw := NewRawDeltaSource()
	if !raw.Initialize(buffer.NewBufferSource(rawData)) {
		t.Fatal("raw source initialization failed")
	}
	if _, ok := raw.GetNext(); ok || raw.Done() {
		t.Fatal("zero raw delta was accepted")
	}

	targetData := []byte{5, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F}
	targets := NewTargetSource()
	if !targets.Initialize(buffer.NewBufferSource(targetData)) {
		t.Fatal("target source initialization failed")
	}
	if _, ok := targets.GetNext(); ok || targets.Done() {
		t.Fatal("overflowing target compensation was accepted")
	}
}
