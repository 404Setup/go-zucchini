package zucchini

import (
	"testing"
)

func TestAddressTranslatorBasic(t *testing.T) {
	units := []Unit{
		{OffsetBegin: 0x1000, OffsetSize: 0x1000, RVABegin: 0x4000, RVASize: 0x1000},
		{OffsetBegin: 0x2000, OffsetSize: 0x0800, RVABegin: 0x6000, RVASize: 0x1000}, // Dangling RVA: 0x6800 to 0x7000
	}

	translator := NewAddressTranslator()
	status := translator.Initialize(units)
	if status != AddressTranslatorSuccess {
		t.Fatalf("Initialize failed: %s", status.String())
	}

	if translator.FakeOffsetBegin() != 0x2800 {
		t.Fatalf("Expected fakeOffsetBegin = 0x2800, got 0x%X", translator.FakeOffsetBegin())
	}

	// Normal offset to RVA
	rva := translator.OffsetToRVA(0x1200)
	if rva != 0x4200 {
		t.Fatalf("OffsetToRVA(0x1200) = 0x%X, expected 0x4200", rva)
	}

	// Normal RVA to offset
	offset := translator.RVAToOffset(0x4200)
	if offset != 0x1200 {
		t.Fatalf("RVAToOffset(0x4200) = 0x%X, expected 0x1200", offset)
	}

	// Dangling RVA translation
	// RVA 0x6900 is in 0x6000+0x1000, delta = 0x900 >= offsetSize 0x800
	// Fake offset = fakeOffsetBegin (0x2800) + RVA (0x6900) = 0x9100
	fakeOffset := translator.RVAToOffset(0x6900)
	if fakeOffset != 0x2800+0x6900 {
		t.Fatalf("RVAToOffset(0x6900) = 0x%X, expected 0x%X", fakeOffset, 0x2800+0x6900)
	}

	// Translate fake offset back to RVA
	backRVA := translator.OffsetToRVA(fakeOffset)
	if backRVA != 0x6900 {
		t.Fatalf("OffsetToRVA(0x%X) = 0x%X, expected 0x6900", fakeOffset, backRVA)
	}

	// Invalid offset
	if translator.OffsetToRVA(0x0500) != InvalidRVA {
		t.Fatalf("Expected InvalidRVA for unmapped offset")
	}

	// Test caches
	offCache := NewOffsetToRVACache(translator)
	if offCache.Convert(0x1200) != 0x4200 {
		t.Fatalf("OffsetToRVACache failed")
	}

	rvaCache := NewRVAToOffsetCache(translator)
	if rvaCache.Convert(0x4200) != 0x1200 {
		t.Fatalf("RVAToOffsetCache failed")
	}
}
