package zucchini

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTripEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		old  []byte
		new  []byte
	}{
		{name: "single byte replacement", old: []byte{0}, new: []byte{1}},
		{name: "grow", old: []byte("x"), new: []byte("new contents")},
		{name: "shrink", old: []byte("old contents"), new: []byte("x")},
		{name: "identical", old: []byte("same same same"), new: []byte("same same same")},
		{name: "binary", old: []byte{0, 1, 2, 0xFF, 4}, new: []byte{0xFF, 1, 3, 0, 4, 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patchBytes, err := GenerateBuffer(test.old, test.new)
			if err != nil {
				t.Fatalf("GenerateBuffer: %v", err)
			}
			got, err := Apply(test.old, patchBytes)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if !bytes.Equal(got, test.new) {
				t.Fatalf("round trip = %v, want %v", got, test.new)
			}
		})
	}
}

func TestApplyRejectsInvalidPatches(t *testing.T) {
	for name, patchBytes := range map[string][]byte{
		"empty":     nil,
		"truncated": []byte("not a patch"),
	} {
		t.Run(name, func(t *testing.T) {
			if output, err := Apply(nil, patchBytes); output != nil {
				t.Fatalf("Apply returned %d output bytes", len(output))
			} else {
				assertErrorCode(t, err, StatusPatchReadError)
			}
			assertErrorCode(t, ApplyTo(nil, patchBytes, nil), StatusPatchReadError)
		})
	}

	patchBytes, err := GenerateBuffer([]byte("expected old"), []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := Apply([]byte("wrong old"), patchBytes)
	if output != nil {
		t.Fatalf("Apply returned %d bytes for a mismatched old image", len(output))
	}
	assertErrorCode(t, err, StatusInvalidOldImage)
	assertErrorCode(t, ApplyTo([]byte("wrong old"), patchBytes, make([]byte, 3)), StatusInvalidOldImage)
}

func assertErrorCode(t *testing.T, err error, want StatusCode) {
	t.Helper()
	var zucchiniErr *Error
	if !errors.As(err, &zucchiniErr) || zucchiniErr.Code != want {
		t.Fatalf("error = %v, want status %v", err, want)
	}
}
