package buffer

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBufferSinkAndSource(t *testing.T) {
	buf := make([]byte, 100)
	sink := NewBufferSink(buf)

	if !sink.PutUint8(0x42) {
		t.Fatal("PutUint8 failed")
	}
	if !sink.PutUint16LE(0x1234) {
		t.Fatal("PutUint16LE failed")
	}
	if !sink.PutUint32LE(0x87654321) {
		t.Fatal("PutUint32LE failed")
	}
	if !sink.PutUint64LE(0x1122334455667788) {
		t.Fatal("PutUint64LE failed")
	}
	if !sink.PutRange([]byte("hello")) {
		t.Fatal("PutRange failed")
	}

	src := NewBufferSource(sink.Bytes())
	v8, ok := src.GetUint8()
	if !ok || v8 != 0x42 {
		t.Fatalf("GetUint8 = %x, ok = %v", v8, ok)
	}

	v16, ok := src.GetUint16LE()
	if !ok || v16 != 0x1234 {
		t.Fatalf("GetUint16LE = %x, ok = %v", v16, ok)
	}

	v32, ok := src.GetUint32LE()
	if !ok || v32 != 0x87654321 {
		t.Fatalf("GetUint32LE = %x, ok = %v", v32, ok)
	}

	v64, ok := src.GetUint64LE()
	if !ok || v64 != 0x1122334455667788 {
		t.Fatalf("GetUint64LE = %x, ok = %v", v64, ok)
	}

	str, ok := src.GetRegion(5)
	if !ok || !bytes.Equal(str, []byte("hello")) {
		t.Fatalf("GetRegion = %s, ok = %v", string(str), ok)
	}
}

func TestLeb128Roundtrip(t *testing.T) {
	uValues := []uint32{0, 1, 127, 128, 255, 300, 16383, 16384, 0xFFFFFFFF, 0x12345678}
	buf := make([]byte, 200)

	sink := NewBufferSink(buf)
	for _, uv := range uValues {
		if !sink.PutUleb128(uv) {
			t.Fatalf("PutUleb128(%d) failed", uv)
		}
	}

	src := NewBufferSource(sink.Bytes())
	for _, uv := range uValues {
		got, ok := src.GetUleb128()
		if !ok || got != uv {
			t.Fatalf("GetUleb128 expected %d, got %d, ok=%v", uv, got, ok)
		}
	}

	sValues := []int32{0, 1, -1, 63, -64, 64, -65, 8191, -8192, 123456, -123456, mathMinInt32(), mathMaxInt32()}
	sink = NewBufferSink(buf)
	for _, sv := range sValues {
		if !sink.PutSleb128(sv) {
			t.Fatalf("PutSleb128(%d) failed", sv)
		}
	}

	src = NewBufferSource(sink.Bytes())
	for _, sv := range sValues {
		got, ok := src.GetSleb128()
		if !ok || got != sv {
			t.Fatalf("GetSleb128 expected %d, got %d, ok=%v", sv, got, ok)
		}
	}
}

func TestBufferSourceRejectsInvalidBoundsAndOverflow(t *testing.T) {
	source := NewBufferSourceFromOffset([]byte{1, 2, 3}, -1)
	if source.Cursor() != 0 {
		t.Fatalf("negative starting offset produced cursor %d", source.Cursor())
	}
	if source.Skip(-1) || source.Cursor() != 0 {
		t.Fatal("negative skip changed the source cursor")
	}
	if _, ok := source.GetRegion(-1); ok || source.Cursor() != 0 {
		t.Fatal("negative region size was accepted")
	}

	if _, ok := NewBufferSource([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x1F}).GetUleb128(); ok {
		t.Fatal("overflowing uint32 LEB128 was accepted")
	}
	if _, ok := NewBufferSource([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}).GetSleb128(); ok {
		t.Fatal("overflowing int32 LEB128 was accepted")
	}
}

func TestBufferSourceCursorOperations(t *testing.T) {
	source := NewBufferSourceFromOffset([]byte{1, 2, 3, 4, 5, 0x81, 0x01}, 99)
	if source.Cursor() != 7 || source.Remaining() != 0 {
		t.Fatalf("clamped source = cursor %d, remaining %d", source.Cursor(), source.Remaining())
	}

	source = NewBufferSource([]byte{1, 2, 3, 4, 5, 0x81, 0x01})
	if !source.CheckNextBytes([]byte{1, 2}) || source.CheckNextBytes([]byte{2}) {
		t.Fatal("CheckNextBytes returned an incorrect result")
	}
	if !source.ConsumeBytes([]byte{1, 2}) || source.ConsumeBytes([]byte{9}) {
		t.Fatal("ConsumeBytes returned an incorrect result")
	}
	if !bytes.Equal(source.RegionFrom(0), []byte{1, 2}) || source.RegionFrom(-1) != nil || source.RegionFrom(3) != nil {
		t.Fatal("RegionFrom returned an incorrect region")
	}
	if !bytes.Equal(source.Bytes(), []byte{3, 4, 5, 0x81, 0x01}) {
		t.Fatalf("Bytes() = %v", source.Bytes())
	}
	value, ok := source.GetInt32LE()
	// Read bytes 03 04 05 81 as a signed little-endian integer.
	if !ok || uint32(value) != 0x81050403 {
		t.Fatalf("GetInt32LE() = %#x, %v", uint32(value), ok)
	}
	if !source.SkipLeb128() || source.Remaining() != 0 {
		t.Fatal("SkipLeb128 did not consume a valid value")
	}
	if source.SkipLeb128() {
		t.Fatal("SkipLeb128 accepted an empty value")
	}

	source = NewBufferSource([]byte{1, 2})
	if source.Skip(3) || source.Cursor() != 2 {
		t.Fatal("oversized Skip did not fail at the end of the buffer")
	}
	if source.CheckNextBytes([]byte{1}) {
		t.Fatal("CheckNextBytes matched beyond the end")
	}
}

func TestWriterSinkMatchesBufferSink(t *testing.T) {
	bufferData := make([]byte, 128)
	bufferSink := NewBufferSink(bufferData)
	var output bytes.Buffer
	writerSink := NewWriterSink(&output)

	writeValues := func(sink Sink) bool {
		return sink.PutUint8(0x42) &&
			sink.PutUint16LE(0x1234) &&
			sink.PutUint32LE(0x87654321) &&
			sink.PutUint64LE(0x1122334455667788) &&
			sink.PutInt32LE(-123456) &&
			sink.PutUleb128(0xffffffff) &&
			sink.PutSleb128(-2147483648) &&
			sink.PutRange([]byte("zucchini"))
	}
	if !writeValues(bufferSink) || !writeValues(writerSink) {
		t.Fatalf("serialization failed: writer error=%v", writerSink.Err())
	}
	if writerSink.Cursor() != int64(bufferSink.Cursor()) {
		t.Fatalf("writer cursor=%d, buffer cursor=%d", writerSink.Cursor(), bufferSink.Cursor())
	}
	if !bytes.Equal(output.Bytes(), bufferSink.Bytes()) {
		t.Fatalf("writer bytes %x differ from buffer bytes %x", output.Bytes(), bufferSink.Bytes())
	}
}

type failingWriter struct {
	remaining int
	err       error
}

func (w *failingWriter) Write(data []byte) (int, error) {
	if w.remaining == 0 {
		return 0, w.err
	}
	n := min(len(data), w.remaining)
	w.remaining -= n
	if n < len(data) {
		return n, nil
	}
	return n, nil
}

func TestWriterSinkRetainsWriteError(t *testing.T) {
	wantErr := errors.New("write failed")
	sink := NewWriterSink(&failingWriter{remaining: 3, err: wantErr})
	if sink.PutRange([]byte("abcdef")) {
		t.Fatal("PutRange unexpectedly succeeded")
	}
	if !errors.Is(sink.Err(), wantErr) {
		t.Fatalf("Err()=%v, want %v", sink.Err(), wantErr)
	}
	if sink.Cursor() != 3 {
		t.Fatalf("Cursor()=%d, want 3", sink.Cursor())
	}
	if sink.PutUint8(1) {
		t.Fatal("write after failure unexpectedly succeeded")
	}
	if !errors.Is(sink.Err(), wantErr) || errors.Is(sink.Err(), io.ErrShortWrite) {
		t.Fatalf("first error was not retained: %v", sink.Err())
	}
}

func mathMinInt32() int32 {
	return -2147483648
}

func mathMaxInt32() int32 {
	return 2147483647
}
