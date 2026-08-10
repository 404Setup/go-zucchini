package disasm

import (
	"encoding/binary"
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

func TestRelocReaderElfAlignsStructBounds(t *testing.T) {
	image := make([]byte, 64)
	putRela32 := func(location int, target types.RVA) {
		binary.LittleEndian.PutUint32(image[location:], uint32(target))
		binary.LittleEndian.PutUint32(image[location+4:], R_386_RELATIVE)
	}
	putRela32(8, 0x1004)
	putRela32(20, 0x1008)

	translator := NewAddressTranslator()
	if status := translator.Initialize([]types.Unit{{
		OffsetBegin: 0, OffsetSize: 64, RVABegin: 0x1000, RVASize: 64,
	}}); status != AddressTranslatorSuccess {
		t.Fatalf("Initialize() = %v", status)
	}

	reader := NewRelocReaderElf(image, types.Bit32, []SectionDimensionsElf{{
		Region: types.BufferRegion{Offset: 8, Size: 24}, EntrySize: 12,
	}}, R_386_RELATIVE, 9, 21, translator)

	ref, ok := reader.GetNext()
	if !ok || ref != (types.Reference{Location: 20, Target: 8}) {
		t.Fatalf("GetNext() = %#v, %v", ref, ok)
	}
	if _, ok := reader.GetNext(); ok {
		t.Fatal("GetNext() returned an unexpected second reference")
	}
}

func TestRelocReaderElfRejectsWideRVAAndTruncatedTarget(t *testing.T) {
	image := make([]byte, 48)
	binary.LittleEndian.PutUint64(image[8:], uint64(1)<<32|0x1000)
	binary.LittleEndian.PutUint64(image[16:], R_X86_64_RELATIVE)
	binary.LittleEndian.PutUint64(image[24:], 0x102C)
	binary.LittleEndian.PutUint64(image[32:], R_X86_64_RELATIVE)

	translator := NewAddressTranslator()
	if status := translator.Initialize([]types.Unit{{
		OffsetBegin: 0, OffsetSize: 48, RVABegin: 0x1000, RVASize: 48,
	}}); status != AddressTranslatorSuccess {
		t.Fatalf("Initialize() = %v", status)
	}

	reader := NewRelocReaderElf(image, types.Bit64, []SectionDimensionsElf{{
		Region: types.BufferRegion{Offset: 8, Size: 32}, EntrySize: 16,
	}}, R_X86_64_RELATIVE, 0, 48, translator)
	if _, ok := reader.GetNext(); ok {
		t.Fatal("GetNext() accepted an unrepresentable RVA or truncated target")
	}
}
