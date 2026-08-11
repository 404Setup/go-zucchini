package zucchini

import "testing"

func TestStatusCodeString(t *testing.T) {
	tests := []struct {
		code StatusCode
		want string
	}{
		{StatusSuccess, "Success"},
		{StatusInvalidParam, "Invalid parameter"},
		{StatusFileReadError, "File read error"},
		{StatusFileWriteError, "File write error"},
		{StatusPatchReadError, "Patch read error"},
		{StatusPatchWriteError, "Patch write error"},
		{StatusInvalidOldImage, "Invalid old image"},
		{StatusInvalidNewImage, "Invalid new image"},
		{StatusDiskFull, "Disk full"},
		{StatusIoError, "I/O error"},
		{StatusFatal, "Fatal error"},
		{StatusCode(99), "Unknown status code (99)"},
	}
	for _, test := range tests {
		if got := test.code.String(); got != test.want {
			t.Errorf("StatusCode(%d).String() = %q, want %q", test.code, got, test.want)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	if got := NewError(StatusInvalidParam, "bad option").Error(); got != "zucchini: Invalid parameter - bad option" {
		t.Fatalf("Error() with message = %q", got)
	}
	if got := NewError(StatusFatal, "").Error(); got != "zucchini: Fatal error" {
		t.Fatalf("Error() without message = %q", got)
	}
}
