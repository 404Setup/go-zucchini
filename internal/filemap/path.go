package filemap

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SameFile reports whether two paths identify the same filesystem entry. It
// also recognizes equivalent paths when one of the entries does not yet exist.
func SameFile(pathA, pathB string) bool {
	infoA, errA := os.Stat(pathA)
	infoB, errB := os.Stat(pathB)
	if errA == nil && errB == nil && os.SameFile(infoA, infoB) {
		return true
	}
	absA, errA := filepath.Abs(pathA)
	absB, errB := filepath.Abs(pathB)
	if errA != nil || errB != nil {
		return false
	}
	absA, absB = filepath.Clean(absA), filepath.Clean(absB)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(absA, absB)
	}
	return absA == absB
}
