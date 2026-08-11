package disasm

import (
	"slices"
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

func TestAddressTranslatorInitializationErrors(t *testing.T) {
	tests := []struct {
		name  string
		units []types.Unit
		want  AddressTranslatorStatus
	}{
		{
			name:  "range overflow",
			units: []types.Unit{{OffsetBegin: types.InvalidOffset, RVASize: 1}},
			want:  AddressTranslatorErrorOverflow,
		},
		{
			name: "inconsistent overlap",
			units: []types.Unit{
				{OffsetBegin: 0, OffsetSize: 100, RVABegin: 100, RVASize: 100},
				{OffsetBegin: 20, OffsetSize: 100, RVABegin: 150, RVASize: 100},
			},
			want: AddressTranslatorErrorBadOverlap,
		},
		{
			name: "dangling overlap",
			units: []types.Unit{
				{OffsetBegin: 0, OffsetSize: 50, RVABegin: 100, RVASize: 100},
				{OffsetBegin: 20, OffsetSize: 80, RVABegin: 120, RVASize: 80},
			},
			want: AddressTranslatorErrorBadOverlapDanglingRVA,
		},
		{
			name:  "fake offset overflow",
			units: []types.Unit{{OffsetBegin: 0xF0000000, OffsetSize: 0x100, RVABegin: 0x20000000, RVASize: 0x100}},
			want:  AddressTranslatorErrorFakeOffsetBeginTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NewAddressTranslator().Initialize(test.units); got != test.want {
				t.Fatalf("Initialize() = %v, want %v", got, test.want)
			}
		})
	}

	statuses := []AddressTranslatorStatus{
		AddressTranslatorSuccess,
		AddressTranslatorErrorOverflow,
		AddressTranslatorErrorBadOverlap,
		AddressTranslatorErrorBadOverlapDanglingRVA,
		AddressTranslatorErrorFakeOffsetBeginTooLarge,
		AddressTranslatorStatus(99),
	}
	for _, status := range statuses {
		if status.String() == "" {
			t.Fatalf("status %d has an empty String()", status)
		}
	}
}

func TestAddressTranslatorNormalizationAndCaches(t *testing.T) {
	translator := NewAddressTranslator()
	units := []types.Unit{
		{},
		{OffsetBegin: 0x300, OffsetSize: 0x80, RVABegin: 0x2000, RVASize: 0x100},
		{OffsetBegin: 0x100, OffsetSize: 0x100, RVABegin: 0x1000, RVASize: 0x100},
		{OffsetBegin: 0x100, OffsetSize: 0x100, RVABegin: 0x1000, RVASize: 0x100},
	}
	if got := translator.Initialize(units); got != AddressTranslatorSuccess {
		t.Fatalf("Initialize() = %v", got)
	}
	if translator.FakeOffsetBegin() != 0x380 {
		t.Fatalf("FakeOffsetBegin() = %#x, want 0x380", translator.FakeOffsetBegin())
	}
	if got := translator.UnitsSortedByOffset(); len(got) != 2 || got[0].OffsetBegin != 0x100 {
		t.Fatalf("UnitsSortedByOffset() = %#v", got)
	}
	if got := translator.UnitsSortedByRVA(); len(got) != 2 || got[0].RVABegin != 0x1000 {
		t.Fatalf("UnitsSortedByRVA() = %#v", got)
	}

	if translator.OffsetToRVA(0x120) != 0x1020 || translator.RVAToOffset(0x1020) != 0x120 {
		t.Fatal("normal translation failed")
	}
	fake := types.Offset(0x380 + 0x20F0)
	if translator.RVAToOffset(0x20F0) != fake || translator.OffsetToRVA(fake) != 0x20F0 {
		t.Fatal("dangling translation failed")
	}
	if translator.OffsetToRVA(0) != types.InvalidRVA || translator.RVAToOffset(0) != types.InvalidOffset {
		t.Fatal("unmapped address was translated")
	}

	offsets := NewOffsetToRVACache(translator)
	if offsets.Convert(0x120) != 0x1020 || offsets.Convert(0x121) != 0x1021 || offsets.Convert(fake) != 0x20F0 {
		t.Fatal("offset cache returned an incorrect translation")
	}
	rvas := NewRVAToOffsetCache(translator)
	if rvas.IsValid(types.InvalidRVA) || rvas.IsValid(0) || !rvas.IsValid(0x1020) {
		t.Fatal("RVA cache validity check is incorrect")
	}
	if rvas.Convert(0x1020) != 0x120 || rvas.Convert(0) != types.InvalidOffset {
		t.Fatal("RVA cache returned an incorrect translation")
	}

	// Initialize must not retain or mutate the caller's order.
	if !slices.Equal(units, []types.Unit{
		{},
		{OffsetBegin: 0x300, OffsetSize: 0x80, RVABegin: 0x2000, RVASize: 0x100},
		{OffsetBegin: 0x100, OffsetSize: 0x100, RVABegin: 0x1000, RVASize: 0x100},
		{OffsetBegin: 0x100, OffsetSize: 0x100, RVABegin: 0x1000, RVASize: 0x100},
	}) {
		t.Fatal("Initialize mutated its input slice")
	}
}
