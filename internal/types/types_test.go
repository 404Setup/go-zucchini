package types

import "testing"

func TestTypeValueMethods(t *testing.T) {
	if Bit32.Width() != 4 || Bit64.Width() != 8 {
		t.Fatalf("bitness widths = (%d, %d), want (4, 8)", Bit32.Width(), Bit64.Width())
	}

	names := map[ExecutableType]string{
		ExecutableTypeNoOp:       "NoOp",
		ExecutableTypeWin32X86:   "Win32X86",
		ExecutableTypeWin32X64:   "Win32X64",
		ExecutableTypeElfX86:     "ElfX86",
		ExecutableTypeElfX64:     "ElfX64",
		ExecutableTypeElfAArch32: "ElfAArch32",
		ExecutableTypeElfAArch64: "ElfAArch64",
		ExecutableTypeDex:        "Dex",
		ExecutableTypeZtf:        "Ztf",
		ExecutableType(123):      "ExecutableType(123)",
	}
	for typ, want := range names {
		if got := typ.String(); got != want {
			t.Errorf("ExecutableType(%d).String() = %q, want %q", typ, got, want)
		}
	}

	region := BufferRegion{Offset: 7, Size: 11}
	if region.Hi() != 18 {
		t.Fatalf("BufferRegion.Hi() = %d, want 18", region.Hi())
	}
	eq := Equivalence{SrcOffset: 10, DstOffset: 20, Length: 5}
	if eq.SrcEnd() != 15 || eq.DstEnd() != 25 {
		t.Fatalf("equivalence ends = (%d, %d), want (15, 25)", eq.SrcEnd(), eq.DstEnd())
	}
	elem := Element{Region: region}
	if elem.EndOffset() != 18 {
		t.Fatalf("Element.EndOffset() = %d, want 18", elem.EndOffset())
	}
}

func TestUnitTranslations(t *testing.T) {
	unit := Unit{OffsetBegin: 100, OffsetSize: 20, RVABegin: 1000, RVASize: 30}
	if unit.OffsetEnd() != 120 || unit.RVAEnd() != 1030 || unit.IsEmpty() {
		t.Fatalf("unexpected unit bounds: %#v", unit)
	}
	if !unit.CoversOffset(100) || !unit.CoversOffset(119) || unit.CoversOffset(120) {
		t.Fatal("CoversOffset boundary handling is incorrect")
	}
	if !unit.CoversRVA(1000) || !unit.CoversRVA(1029) || unit.CoversRVA(1030) {
		t.Fatal("CoversRVA boundary handling is incorrect")
	}
	if unit.CoversDanglingRVA(1019) || !unit.CoversDanglingRVA(1020) || !unit.HasDanglingRVA() {
		t.Fatal("dangling RVA detection is incorrect")
	}
	if got := unit.OffsetToRVAUnsafe(105); got != 1005 {
		t.Fatalf("OffsetToRVAUnsafe() = %d, want 1005", got)
	}
	if got := unit.RVAToOffsetUnsafe(1005, 5000); got != 105 {
		t.Fatalf("normal RVAToOffsetUnsafe() = %d, want 105", got)
	}
	if got := unit.RVAToOffsetUnsafe(1025, 5000); got != 6025 {
		t.Fatalf("dangling RVAToOffsetUnsafe() = %d, want 6025", got)
	}
	if !(Unit{}).IsEmpty() || (Unit{OffsetSize: 2, RVASize: 2}).HasDanglingRVA() {
		t.Fatal("empty or non-dangling unit classification is incorrect")
	}
}
