package patch

import (
	"bytes"
	"testing"

	"github.com/404Setup/go-zucchini/internal/buffer"
)

func TestExtraDataSinkSerializesBorrowedParts(t *testing.T) {
	image := []byte("--abc--defg--")
	sink := NewExtraDataSink(image)
	if !sink.PutRegion(2, 3) || !sink.PutRegion(7, 4) || !sink.PutRegion(0, 0) {
		t.Fatal("PutRegion rejected a valid region")
	}

	if got, want := sink.SerializedSize(), 4+7; got != want {
		t.Fatalf("serialized size = %d, want %d", got, want)
	}
	out := make([]byte, sink.SerializedSize())
	if !sink.SerializeInto(buffer.NewBufferSink(out)) {
		t.Fatal("SerializeInto failed")
	}
	want := append([]byte{7, 0, 0, 0}, []byte("abcdefg")...)
	if !bytes.Equal(out, want) {
		t.Fatalf("serialized data = %v, want %v", out, want)
	}
}

func TestExtraDataSinkDoesNotCopyParts(t *testing.T) {
	image := []byte("before")
	sink := NewExtraDataSink(image)
	if !sink.PutRegion(0, len(image)) {
		t.Fatal("PutRegion rejected a valid region")
	}
	image[0] = 'B'

	out := make([]byte, sink.SerializedSize())
	if !sink.SerializeInto(buffer.NewBufferSink(out)) {
		t.Fatal("SerializeInto failed")
	}
	if got := string(out[4:]); got != "Before" {
		t.Fatalf("serialized borrowed data = %q, want %q", got, "Before")
	}
}

func TestExtraDataSinkRejectsInvalidRegions(t *testing.T) {
	sink := NewExtraDataSink([]byte("abc"))
	for _, tc := range []struct{ offset, length int }{{-1, 1}, {0, -1}, {2, 2}, {4, 0}} {
		if sink.PutRegion(tc.offset, tc.length) {
			t.Fatalf("PutRegion(%d, %d) accepted an invalid region", tc.offset, tc.length)
		}
	}
}
