package zucchini

import "fmt"

// StatusCode represents a Zucchini operation status code.
// It matches the exit codes and status codes of Chromium's Zucchini library.
type StatusCode int

const (
	StatusSuccess         StatusCode = 0
	StatusInvalidParam    StatusCode = 1
	StatusFileReadError   StatusCode = 2
	StatusFileWriteError  StatusCode = 3
	StatusPatchReadError  StatusCode = 4
	StatusPatchWriteError StatusCode = 5
	StatusInvalidOldImage StatusCode = 6
	StatusInvalidNewImage StatusCode = 7
	StatusDiskFull        StatusCode = 8
	StatusIoError         StatusCode = 9
	StatusFatal           StatusCode = 10

	// Alias for backwards compatibility
	StatusInvalidPatch StatusCode = StatusPatchReadError
)

func (s StatusCode) String() string {
	switch s {
	case StatusSuccess:
		return "Success"
	case StatusInvalidParam:
		return "Invalid parameter"
	case StatusFileReadError:
		return "File read error"
	case StatusFileWriteError:
		return "File write error"
	case StatusPatchReadError:
		return "Patch read error"
	case StatusPatchWriteError:
		return "Patch write error"
	case StatusInvalidOldImage:
		return "Invalid old image"
	case StatusInvalidNewImage:
		return "Invalid new image"
	case StatusDiskFull:
		return "Disk full"
	case StatusIoError:
		return "I/O error"
	case StatusFatal:
		return "Fatal error"
	default:
		return fmt.Sprintf("Unknown status code (%d)", int(s))
	}
}

// Error represents a Zucchini operation error containing a StatusCode and descriptive message.
type Error struct {
	Code    StatusCode
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("zucchini: %s - %s", e.Code.String(), e.Message)
	}
	return fmt.Sprintf("zucchini: %s", e.Code.String())
}

// NewError returns a new Zucchini Error with the given status code and message.
func NewError(code StatusCode, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}
