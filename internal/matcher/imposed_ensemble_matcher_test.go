package matcher

import (
	"testing"

	"github.com/404Setup/go-zucchini/internal/types"
)

func testElementDetector(image []byte) (types.Element, bool) {
	if len(image) == 0 || image[0] == 'U' {
		return types.Element{}, false
	}
	exeType := types.ExecutableTypeElfX86
	if image[0] == 'B' {
		exeType = types.ExecutableTypeElfX64
	}
	return types.Element{Region: types.BufferRegion{Size: 1}, ExeType: exeType}, true
}

func TestImposedMatcherMatchesCppSemantics(t *testing.T) {
	oldImage := []byte("AoldA123Uold")
	newImage := []byte("AnewA123Unew")
	m := NewImposedEnsembleMatcher("8+4=8+4, 0+4=0+4, 4+4=4+4")
	if !m.runMatchWithDetector(oldImage, newImage, testElementDetector) {
		t.Fatal("valid imposed matches rejected")
	}
	if m.NumIdentical() != 1 {
		t.Fatalf("NumIdentical() = %d, want 1", m.NumIdentical())
	}
	if len(m.Matches()) != 1 {
		t.Fatalf("len(Matches()) = %d, want 1", len(m.Matches()))
	}
	match := m.Matches()[0]
	if match.OldElement.Region != (types.BufferRegion{Offset: 0, Size: 4}) ||
		match.NewElement.Region != (types.BufferRegion{Offset: 0, Size: 4}) {
		t.Fatalf("imposed regions were changed: %+v", match)
	}
}

func TestImposedMatcherRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		imposed string
		old     []byte
		new     []byte
	}{
		{"zero size", "0+0=0+1", []byte("A"), []byte("A")},
		{"trailing comma", "0+1=0+1,", []byte("A"), []byte("A")},
		{"overlap in new", "0+2=0+2,2+2=1+2", []byte("AABB"), []byte("AABB")},
		{"type mismatch", "0+2=0+2", []byte("Ax"), []byte("Bx")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewImposedEnsembleMatcher(tc.imposed)
			if m.runMatchWithDetector(tc.old, tc.new, testElementDetector) {
				t.Fatal("invalid imposed match accepted")
			}
		})
	}
}
