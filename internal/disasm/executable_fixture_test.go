package disasm

import (
	"encoding/binary"
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

func TestSyntheticPE64ReferenceGroups(t *testing.T) {
	image := makeReferencePE64()
	d, ok := NewDisassemblerWin32X64(image)
	if !ok {
		t.Fatal("synthetic PE64 image was rejected")
	}
	if d.GetExeType() != types.ExecutableTypeWin32X64 || d.GetExeTypeString() != "Windows PE / x64" ||
		d.Size() != len(image) || len(d.Image()) != len(image) || d.NumEquivalenceIterations() != 2 {
		t.Fatalf("unexpected PE metadata: type=%v name=%q size=%d image=%d iterations=%d",
			d.GetExeType(), d.GetExeTypeString(), d.Size(), len(d.Image()), d.NumEquivalenceIterations())
	}

	groups := d.MakeReferenceGroups()
	if len(groups) != 3 || d.Abs32Len() == 0 || d.Rel32Len() < 2 {
		t.Fatalf("groups=%d abs32=%d rel32=%d", len(groups), d.Abs32Len(), d.Rel32Len())
	}
	total := 0
	for _, group := range groups {
		if group.Width() == 0 || group.TypeTag() == types.NoTypeTag || group.PoolTag() == types.NoPoolTag {
			t.Fatalf("invalid group traits: %#v", group.Traits)
		}
		reader := group.GetReader(0, types.Offset(len(image)))
		for {
			ref, ok := reader.GetNext()
			if !ok {
				break
			}
			if ref.Location >= types.Offset(len(image)) || ref.Target >= types.Offset(len(image)) {
				t.Fatalf("out-of-range reference: %#v", ref)
			}
			group.GetWriter(image).PutNext(ref)
			total++
		}
	}
	if total == 0 {
		t.Fatal("no PE references were returned")
	}
}

func TestSyntheticElf64ReferenceGroups(t *testing.T) {
	image := makeReferenceElf64()
	d, ok := NewDisassemblerElfX64(image)
	if !ok {
		t.Fatal("synthetic ELF64 image was rejected")
	}
	if d.GetExeType() != types.ExecutableTypeElfX64 || d.GetExeTypeString() != "ELF / x64" ||
		d.Size() != 0x240 || len(d.Image()) != 0x240 || d.NumEquivalenceIterations() != 2 {
		t.Fatalf("unexpected ELF metadata: type=%v name=%q size=%d image=%d iterations=%d",
			d.GetExeType(), d.GetExeTypeString(), d.Size(), len(d.Image()), d.NumEquivalenceIterations())
	}
	if _, ok := NewDisassemblerElfX86(image); ok {
		t.Fatal("ELF64 image was accepted by the ELF32 parser")
	}
	groups := d.MakeReferenceGroups()
	if len(groups) != 3 {
		t.Fatalf("reference group count = %d, want 3", len(groups))
	}
	refs := groups[2].GetReader(0, types.Offset(d.Size()))
	ref, ok := refs.GetNext()
	if !ok || ref.Location != 0x111 || ref.Target != 0x140 {
		t.Fatalf("relative ELF reference = %#v, %v, want location 0x111 target 0x140", ref, ok)
	}
	groups[2].GetWriter(image).PutNext(ref)
	if _, ok := refs.GetNext(); ok {
		t.Fatal("unexpected second ELF relative reference")
	}
}

func TestAbsoluteAddressAndGapUtilities(t *testing.T) {
	translator := NewAddressTranslator()
	if status := translator.Initialize([]types.Unit{{
		OffsetBegin: 16, OffsetSize: 32, RVABegin: 0x1000, RVASize: 32,
	}}); status != AddressTranslatorSuccess {
		t.Fatal(status)
	}
	image := make([]byte, 64)
	address := NewAbsoluteAddress(types.Bit64, 0x140000000)
	if !address.Write(image, 8, 0x1004) {
		t.Fatal("AbsoluteAddress.Write rejected a valid location")
	}
	if got, ok := address.Read(image, 8); !ok || got != 0x1004 {
		t.Fatalf("AbsoluteAddress.Read = %#x, %v", got, ok)
	}
	if address.Write(image, 60, 1) {
		t.Fatal("AbsoluteAddress.Write accepted a truncated destination")
	}
	if _, ok := address.Read(image, 60); ok {
		t.Fatal("AbsoluteAddress.Read accepted a truncated source")
	}

	locations := []types.Offset{8, 10, 24, 40}
	binary.LittleEndian.PutUint64(image[24:], 0x140001008)
	binary.LittleEndian.PutUint64(image[40:], 1)
	if removed := RemoveUntranslatableAbs32(image, types.Bit64, 0x140000000, translator, &locations); removed != 2 {
		t.Fatalf("RemoveUntranslatableAbs32 removed %d entries, want 2", removed)
	}
	locations = []types.Offset{8, 10, 16, 24}
	if removed := RemoveOverlappingAbs32Locations(8, &locations); removed != 1 {
		t.Fatalf("RemoveOverlappingAbs32Locations removed %d entries, want 1", removed)
	}

	finder := NewAbs32GapFinder(make([]byte, 32), types.BufferRegion{Offset: 4, Size: 24}, []types.Offset{8, 20}, 4)
	var gaps []types.BufferRegion
	for finder.FindNext() {
		gaps = append(gaps, finder.GetGap())
	}
	want := []types.BufferRegion{{Offset: 4, Size: 4}, {Offset: 12, Size: 8}, {Offset: 24, Size: 4}}
	if len(gaps) != len(want) {
		t.Fatalf("gaps = %#v, want %#v", gaps, want)
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gap %d = %#v, want %#v", i, gaps[i], want[i])
		}
	}
}

func makeReferencePE64() []byte {
	image := makeMinimalPE64()
	for i := 0x200; i < 0x400; i++ {
		image[i] = byte(i*29 + 7)
	}
	const optionalHeader = 0x98
	const relocationDirectory = optionalHeader + 112 + 5*8
	binary.LittleEndian.PutUint64(image[optionalHeader+24:], 0x140000000)
	binary.LittleEndian.PutUint32(image[relocationDirectory:], 0x1180)
	binary.LittleEndian.PutUint32(image[relocationDirectory+4:], 12)

	image[0x210] = 0xE8
	binary.LittleEndian.PutUint32(image[0x211:], uint32(0x1080-(0x1011+4)))
	image[0x240] = 0xE9
	binary.LittleEndian.PutUint32(image[0x241:], uint32(0x10C0-(0x1041+4)))
	binary.LittleEndian.PutUint64(image[0x280:], 0x1400010C0)
	binary.LittleEndian.PutUint64(image[0x300:], 0x140001080)
	binary.LittleEndian.PutUint32(image[0x380:], 0x1000)
	binary.LittleEndian.PutUint32(image[0x384:], 12)
	binary.LittleEndian.PutUint16(image[0x388:], 10<<12|0x100)
	binary.LittleEndian.PutUint16(image[0x38A:], 0)
	return image
}

func makeReferenceElf64() []byte {
	image := make([]byte, 0x300)
	copy(image[:4], []byte{0x7F, 'E', 'L', 'F'})
	image[EI_CLASS] = ELFCLASS64
	image[EI_DATA] = 1
	image[EI_VERSION] = 1
	binary.LittleEndian.PutUint16(image[16:], ET_EXEC)
	binary.LittleEndian.PutUint16(image[18:], EM_X86_64)
	binary.LittleEndian.PutUint32(image[20:], 1)
	binary.LittleEndian.PutUint64(image[40:], 0x180)
	binary.LittleEndian.PutUint16(image[52:], 64)
	binary.LittleEndian.PutUint16(image[54:], 56)
	binary.LittleEndian.PutUint16(image[58:], 64)
	binary.LittleEndian.PutUint16(image[60:], 3)
	binary.LittleEndian.PutUint16(image[62:], 1)

	names := []byte("\x00.shstrtab\x00.text\x00")
	copy(image[0x80:], names)
	nameSection := 0x180 + 64
	binary.LittleEndian.PutUint32(image[nameSection+4:], SHT_STRTAB)
	binary.LittleEndian.PutUint64(image[nameSection+24:], 0x80)
	binary.LittleEndian.PutUint64(image[nameSection+32:], uint64(len(names)))

	textSection := 0x180 + 128
	binary.LittleEndian.PutUint32(image[textSection:], 11)
	binary.LittleEndian.PutUint32(image[textSection+4:], SHT_PROGBITS)
	binary.LittleEndian.PutUint64(image[textSection+8:], SHF_ALLOC|SHF_EXECINSTR)
	binary.LittleEndian.PutUint64(image[textSection+16:], 0x1000)
	binary.LittleEndian.PutUint64(image[textSection+24:], 0x100)
	binary.LittleEndian.PutUint64(image[textSection+32:], 0x80)
	binary.LittleEndian.PutUint64(image[textSection+48:], 16)
	for i := 0x100; i < 0x180; i++ {
		image[i] = 0x90
	}
	image[0x110] = 0xE8
	binary.LittleEndian.PutUint32(image[0x111:], uint32(0x1040-(0x1011+4)))
	return image
}
