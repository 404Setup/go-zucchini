package disasm

import "testing"

func TestArm32BranchDisplacementRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		kind  arm32AddrType
		code  uint32
		disps []int32
	}{
		{"A24", arm32A24, 0xEA000000, []int32{-1 << 25, -4, 0, 4, 1<<25 - 4}},
		{"T8", arm32T8, 0xD100, []int32{-1 << 8, -2, 0, 2, 1<<8 - 2}},
		{"T11", arm32T11, 0xE000, []int32{-1 << 11, -2, 0, 2, 1<<11 - 2}},
		{"T20", arm32T20, 0xF0008000, []int32{-1 << 20, -2, 0, 2, 1<<20 - 2}},
		{"T24", arm32T24, 0xF0009000, []int32{-1 << 24, -2, 0, 2, 1<<24 - 2}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, want := range test.disps {
				code, ok := encodeArm32(test.kind, want, test.code)
				if !ok {
					t.Fatalf("encode(%d) failed", want)
				}
				got, _, ok := decodeArm32(test.kind, code)
				if !ok || got != want {
					t.Fatalf("decode(encode(%d)) = %d, %v", want, got, ok)
				}
			}
		})
	}
}

func TestArm64BranchDisplacementRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		kind  arm64AddrType
		code  uint32
		disps []int32
	}{
		{"Immd14", arm64Immd14, 0x36000000, []int32{-1 << 15, -4, 0, 4, 1<<15 - 4}},
		{"Immd19", arm64Immd19, 0x54000000, []int32{-1 << 20, -4, 0, 4, 1<<20 - 4}},
		{"Immd26", arm64Immd26, 0x14000000, []int32{-1 << 27, -4, 0, 4, 1<<27 - 4}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, want := range test.disps {
				code, ok := encodeArm64(test.kind, want, test.code)
				if !ok {
					t.Fatalf("encode(%d) failed", want)
				}
				got, ok := decodeArm64(test.kind, code)
				if !ok || got != want {
					t.Fatalf("decode(encode(%d)) = %d, %v", want, got, ok)
				}
			}
		})
	}
}
