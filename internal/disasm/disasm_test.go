package disasm

import (
	"encoding/binary"
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

func TestDisassemblerNoOp(t *testing.T) {
	data := []byte("hello world zucchini test binary data")
	dis := NewDisassemblerNoOp(data)
	if dis.Size() != len(data) {
		t.Fatalf("Expected size %d, got %d", len(data), dis.Size())
	}
	if dis.GetExeTypeString() != "NoOp" {
		t.Fatalf("Expected ExeTypeString NoOp, got %s", dis.GetExeTypeString())
	}
}

func TestQuickDetectWin32AndElf(t *testing.T) {
	peData := make([]byte, 0x200)
	peData[0] = 'M'
	peData[1] = 'Z'
	binary.LittleEndian.PutUint32(peData[0x3C:], 0x80)
	peData[0x80] = 'P'
	peData[0x81] = 'E'
	peData[0x82] = 0
	peData[0x83] = 0

	if !QuickDetectWin32(peData) {
		t.Fatal("QuickDetectWin32 failed on minimal PE image")
	}

	elfData := make([]byte, 64)
	elfData[0] = 0x7F
	elfData[1] = 'E'
	elfData[2] = 'L'
	elfData[3] = 'F'
	elfData[EI_CLASS] = ELFCLASS32

	if !QuickDetectElf(elfData) {
		t.Fatal("QuickDetectElf failed on minimal ELF image")
	}
}

func TestWin32WriterGroupsDoNotDiscoverReferences(t *testing.T) {
	image := makeMinimalPE64()
	d, ok := NewDisassemblerWin32X64(image)
	if !ok {
		t.Fatal("failed to parse synthetic PE64 image")
	}
	groups := MakeReferenceGroupsForWriter(d)
	if len(groups) != 3 {
		t.Fatalf("got %d writer groups, want 3", len(groups))
	}
	if d.Abs32Len() != 0 || d.Rel32Len() != 0 {
		t.Fatalf("writer groups discovered references: abs32=%d rel32=%d", d.Abs32Len(), d.Rel32Len())
	}
	for _, group := range groups {
		if writer := group.GetWriter(image); writer == nil {
			t.Fatalf("type %d returned a nil writer", group.TypeTag())
		}
	}
}

func TestWin32RejectsPE32PlusForAnotherMachine(t *testing.T) {
	image := makeMinimalPE64()
	fileHeaderOffset := 0x84
	if _, ok := NewDisassemblerWin32X64(image); !ok {
		t.Fatal("minimal AMD64 PE32+ image was rejected")
	}

	const imageFileMachineLoongArch64 = 0x6264
	binary.LittleEndian.PutUint16(image[fileHeaderOffset:], imageFileMachineLoongArch64)
	if _, ok := NewDisassemblerWin32X64(image); ok {
		t.Fatal("LoongArch64 PE32+ image was accepted as x64")
	}
}

func TestWin32RejectsMalformedHeadersWithoutPanic(t *testing.T) {
	truncated := make([]byte, 0x98)
	truncated[0], truncated[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(truncated[0x3C:], 0x80)
	copy(truncated[0x80:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(truncated[0x84:], ImageFileMachineAMD64)
	if _, ok := NewDisassemblerWin32X64(truncated); ok {
		t.Fatal("truncated optional header was accepted")
	}

	tests := map[string]func([]byte){
		"misaligned PE offset": func(image []byte) {
			binary.LittleEndian.PutUint32(image[0x3C:], 0x81)
		},
		"inconsistent directory count": func(image []byte) {
			binary.LittleEndian.PutUint32(image[0x98+108:], 15)
		},
		"section file range overflow": func(image []byte) {
			section := 0x188
			binary.LittleEndian.PutUint32(image[section+16:], 0x40)
			binary.LittleEndian.PutUint32(image[section+20:], 0xFFFFFFF0)
		},
		"section RVA out of image": func(image []byte) {
			section := 0x188
			binary.LittleEndian.PutUint32(image[section+8:], 0x2000)
		},
		"no readable executable section": func(image []byte) {
			binary.LittleEndian.PutUint32(image[0x188+36:], ImageScnMemExecute)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			image := makeMinimalPE64()
			mutate(image)
			if _, ok := NewDisassemblerWin32X64(image); ok {
				t.Fatal("malformed PE was accepted")
			}
		})
	}
}

func TestFindRelocBlocksRejectsMalformedBounds(t *testing.T) {
	image := make([]byte, 16)
	binary.LittleEndian.PutUint32(image[4:], ^uint32(0))
	for name, region := range map[string]types.BufferRegion{
		"negative offset":     {Offset: -1, Size: 8},
		"negative size":       {Offset: 0, Size: -1},
		"range beyond image":  {Offset: 12, Size: 8},
		"block size overflow": {Offset: 0, Size: len(image)},
	} {
		t.Run(name, func(t *testing.T) {
			var offsets []types.Offset
			if FindRelocBlocks(image, region, &offsets) {
				t.Fatal("malformed relocation region was accepted")
			}
		})
	}
}

func makeMinimalPE64() []byte {
	image := make([]byte, 0x400)
	image[0], image[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(image[0x3C:], 0x80)
	copy(image[0x80:], []byte{'P', 'E', 0, 0})
	fileHeader := 0x84
	binary.LittleEndian.PutUint16(image[fileHeader:], ImageFileMachineAMD64)
	binary.LittleEndian.PutUint16(image[fileHeader+2:], 1)
	binary.LittleEndian.PutUint16(image[fileHeader+16:], 0xF0)
	optionalHeader := fileHeader + 20
	binary.LittleEndian.PutUint16(image[optionalHeader:], 0x20B)
	binary.LittleEndian.PutUint64(image[optionalHeader+24:], 0x400000)
	binary.LittleEndian.PutUint32(image[optionalHeader+56:], 0x2000)
	binary.LittleEndian.PutUint32(image[optionalHeader+60:], 0x200)
	binary.LittleEndian.PutUint32(image[optionalHeader+108:], ImageNumberOfDirectoryEntries)
	section := optionalHeader + 0xF0
	copy(image[section:], ".text")
	binary.LittleEndian.PutUint32(image[section+8:], 0x200)
	binary.LittleEndian.PutUint32(image[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(image[section+16:], 0x200)
	binary.LittleEndian.PutUint32(image[section+20:], 0x200)
	binary.LittleEndian.PutUint32(image[section+36:], CodeCharacteristics|0x20)
	return image
}
