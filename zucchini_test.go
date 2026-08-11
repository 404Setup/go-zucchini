package zucchini

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/types"
)

func TestImageSizesFitPatchFormat(t *testing.T) {
	const limit = uint64(0xFFFFFFFF)
	if !imageSizesFitPatchFormat(limit-1, limit-1) {
		t.Fatal("largest representable image sizes were rejected")
	}
	if imageSizesFitPatchFormat(limit, 0) || imageSizesFitPatchFormat(0, limit) {
		t.Fatal("reserved offset sentinel was accepted as an image size")
	}
}

func TestZucchiniGenAndApplyRaw(t *testing.T) {
	oldData := []byte("The quick brown fox jumps over the lazy dog. Zucchini pure Go differential patch engine.")
	newData := []byte("The fast brown fox jumps over the lazy dog! Zucchini pure Go differential patch engine v1.26.")

	patchBytes, err := GenerateBuffer(oldData, newData)
	if err != nil {
		t.Fatalf("GenerateBuffer failed: %v", err)
	}

	if len(patchBytes) == 0 {
		t.Fatal("GenerateBuffer produced empty patch")
	}

	reconstructed, err := Apply(oldData, patchBytes)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(reconstructed, newData) {
		t.Fatalf("Reconstructed data does not match target new data!\nGot:  %s\nWant: %s", string(reconstructed), string(newData))
	}
}

func TestZucchiniGenAndApplyPE(t *testing.T) {
	oldPE := make([]byte, 1024)
	oldPE[0] = 'M'
	oldPE[1] = 'Z'
	oldPE[0x3C] = 0x80
	oldPE[0x80] = 'P'
	oldPE[0x81] = 'E'
	oldPE[0x84] = 0x4C
	oldPE[0x85] = 0x01
	oldPE[0x98] = 0xE0
	oldPE[0x99] = 0x00
	oldPE[0x9C] = 0x0B
	oldPE[0x9D] = 0x01
	for i := 0x100; i < 0x300; i++ {
		oldPE[i] = byte(i & 0xFF)
	}

	newPE := make([]byte, 1024)
	copy(newPE, oldPE)
	for i := 0x200; i < 0x250; i++ {
		newPE[i] = byte((i + 5) & 0xFF)
	}

	patchBytes, err := GenerateBuffer(oldPE, newPE)
	if err != nil {
		t.Fatalf("GenerateBuffer PE failed: %v", err)
	}

	reconstructed, err := Apply(oldPE, patchBytes)
	if err != nil {
		t.Fatalf("Apply PE failed: %v", err)
	}

	if !bytes.Equal(reconstructed, newPE) {
		t.Fatalf("Reconstructed PE binary does not match expected new binary!")
	}
}

func TestZucchiniImposed(t *testing.T) {
	oldData := []byte("0123456789ABCDEF0123456789ABCDEF")
	newData := []byte("0123456789XYZDEF0123456789XYZDEF")

	writer := patch.NewEnsemblePatchWriter(oldData, newData)
	code := GenerateBufferImposed(oldData, newData, "0+16=0+16,16+16=16+16", writer)
	if code != StatusSuccess {
		t.Fatalf("GenerateBufferImposed failed with code %v", code)
	}

	size := writer.SerializedSize()
	patchBytes := make([]byte, size)
	sink := buffer.NewBufferSink(patchBytes)
	if !writer.SerializeInto(sink) {
		t.Fatal("SerializeInto failed")
	}

	reconstructed, err := Apply(oldData, patchBytes)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(reconstructed, newData) {
		t.Fatalf("Reconstructed data does not match target new data!")
	}
}

func TestZucchiniPatchVerification(t *testing.T) {
	oldData := []byte("Test Old Data 12345")
	newData := []byte("Test New Data 67890")

	patchBytes, err := GenerateBuffer(oldData, newData)
	if err != nil {
		t.Fatalf("GenerateBuffer failed: %v", err)
	}

	reader, ok := patch.CreateEnsemblePatchReader(patchBytes)
	if !ok {
		t.Fatal("CreateEnsemblePatchReader returned false for valid patch")
	}

	if !reader.CheckOldFile(oldData) {
		t.Error("CheckOldFile returned false for valid old data")
	}
	if !reader.CheckNewFile(newData) {
		t.Error("CheckNewFile returned false for valid new data")
	}
	if reader.Header().Magic != patch.PatchHeaderMagic {
		t.Errorf("Unexpected magic: 0x%X", reader.Header().Magic)
	}
}

func TestApplyChecksOldImageBeforeAllocatingOutput(t *testing.T) {
	patchBytes := makeHugeOutputPatch()
	output, err := Apply([]byte("does not match"), patchBytes)
	if output != nil || err == nil {
		t.Fatalf("Apply() = (%d bytes, %v), want rejected old image", len(output), err)
	}
	var zucchiniErr *Error
	if !errors.As(err, &zucchiniErr) || zucchiniErr.Code != StatusInvalidOldImage {
		t.Fatalf("Apply() error = %v, want StatusInvalidOldImage", err)
	}
}

func TestApplyBufferRejectsWrongOutputSize(t *testing.T) {
	oldData := []byte("old image")
	newData := []byte("new image")
	patchBytes, err := GenerateBuffer(oldData, newData)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := patch.CreateEnsemblePatchReader(patchBytes)
	if !ok {
		t.Fatal("generated patch was rejected")
	}
	if code := ApplyBuffer(oldData, reader, make([]byte, len(newData)-1)); code != StatusInvalidNewImage {
		t.Fatalf("ApplyBuffer() = %v, want StatusInvalidNewImage", code)
	}
}

func makeHugeOutputPatch() []byte {
	var data []byte
	put16 := func(value uint16) { data = binary.LittleEndian.AppendUint16(data, value) }
	put32 := func(value uint32) { data = binary.LittleEndian.AppendUint32(data, value) }
	putBuffer := func(value []byte) {
		put32(uint32(len(value)))
		data = append(data, value...)
	}

	put32(patch.PatchHeaderMagic)
	put16(2)
	put16(0)
	put32(^uint32(0))
	put32(0)
	put32(^uint32(0))
	put32(0)
	put32(1)
	put32(0)
	put32(^uint32(0))
	put32(0)
	put32(^uint32(0))
	put32(uint32(types.ExecutableTypeNoOp))
	put16(1)
	putBuffer(patch.EncodeVarInt(0))
	putBuffer(patch.EncodeVarUInt(0))
	putBuffer(patch.EncodeVarUInt(uint64(^uint32(0))))
	putBuffer(nil)
	putBuffer(nil)
	putBuffer(nil)
	putBuffer(nil)
	put32(0)
	return data
}

func TestBigPatchMemory(t *testing.T) {
	size := 5 * 1024 * 1024
	oldData := make([]byte, size)
	for i := range oldData {
		oldData[i] = byte(i * 31)
	}
	newData := make([]byte, size+500)
	copy(newData, oldData)
	for i := 10000; i < 15000; i++ {
		newData[i] ^= 0xAA
	}

	patchBytes, err := GenerateBuffer(oldData, newData)
	if err != nil {
		t.Fatalf("GenerateBuffer failed: %v", err)
	}

	t.Logf("Generated 5MB patch size: %d bytes", len(patchBytes))

	reconstructed, err := Apply(oldData, patchBytes)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !bytes.Equal(reconstructed, newData) {
		t.Fatalf("Apply result does not match expected new data!")
	}
}

func TestDisassemblerReferenceDiscovery(t *testing.T) {
	image := makeSyntheticPE64(0)
	d, ok := disasm.NewDisassemblerWin32X64(image)
	if !ok {
		t.Fatal("synthetic PE64 image was rejected")
	}
	groups := d.MakeReferenceGroups()
	if len(groups) != 3 {
		t.Fatalf("reference group count = %d, want 3", len(groups))
	}
	if d.Abs32Len() == 0 {
		t.Fatal("base relocation did not produce absolute-address references")
	}
	if d.Rel32Len() < 2 {
		t.Fatalf("relative reference count = %d, want at least 2", d.Rel32Len())
	}
}
