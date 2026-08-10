package zucchini

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/404Setup/go-zucchini/internal/buffer"
	"github.com/404Setup/go-zucchini/internal/filemap"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/types"
)

// GenerateFileOptions controls file-backed patch generation.
type GenerateFileOptions struct {
	Raw               bool
	ImposedMatches    string
	KeepPartialOutput bool
}

// ApplyFileOptions controls file-backed patch application.
type ApplyFileOptions struct {
	KeepPartialOutput bool
	// ExpectedNewSHA256, when non-nil, must contain the trusted 32-byte SHA-256
	// digest of the reconstructed file. Patch CRC32 fields are not an
	// authenticity mechanism.
	ExpectedNewSHA256 []byte
}

// ApplyFile applies patchPath to oldPath and writes the result to newPath.
// Unix builds use memory mapping. Windows builds use ordinary file I/O unless
// built with the explicit zucchini_mmap tag.
func ApplyFile(oldPath, patchPath, newPath string) (err error) {
	return ApplyFileWithOptions(oldPath, patchPath, newPath, ApplyFileOptions{})
}

// ApplyFileWithOptions applies a patch using the supplied file lifecycle
// options. By default the existing destination is preserved on failure and the
// temporary partial output is removed.
func ApplyFileWithOptions(oldPath, patchPath, newPath string, options ApplyFileOptions) (err error) {
	verifySHA256 := options.ExpectedNewSHA256 != nil
	if verifySHA256 && len(options.ExpectedNewSHA256) != sha256.Size {
		return NewError(StatusInvalidParam, "ExpectedNewSHA256 must contain exactly 32 bytes")
	}
	var expectedSHA256 [sha256.Size]byte
	copy(expectedSHA256[:], options.ExpectedNewSHA256)
	if filemap.SameFile(newPath, oldPath) || filemap.SameFile(newPath, patchPath) {
		return NewError(StatusInvalidParam, "Output path must be different from input paths")
	}
	oldImage, err := filemap.Open(oldPath)
	if err != nil {
		return NewError(StatusFileReadError, fmt.Sprintf("Failed to map old image: %v", err))
	}
	defer closeFileMapping(oldImage, &err)

	patchImage, err := filemap.Open(patchPath)
	if err != nil {
		return NewError(StatusFileReadError, fmt.Sprintf("Failed to map patch: %v", err))
	}
	defer closeFileMapping(patchImage, &err)

	reader, ok := patch.CreateEnsemblePatchReader(patchImage.Data)
	if !ok {
		return NewError(StatusInvalidPatch, "Failed to parse ensemble patch")
	}
	newSize := uint64(reader.Header().NewSize)
	if newSize > uint64(maxIntValue()) {
		return NewError(StatusInvalidNewImage, "New image is too large for this platform")
	}
	if !reader.CheckOldFile(oldImage.Data) {
		return NewError(StatusInvalidOldImage, "Old image does not match patch")
	}

	tempFile, err := createPatchTemp(newPath)
	if err != nil {
		return NewError(StatusFileWriteError, fmt.Sprintf("Failed to reserve temporary output: %v", err))
	}
	tempPath := tempFile.Name()
	removeTemp := true
	defer func() {
		if !removeTemp {
			return
		}
		if options.KeepPartialOutput && err != nil {
			if renameErr := os.Rename(tempPath, newPath); renameErr != nil {
				err = fmt.Errorf("%w; failed to retain partial output %q: %v", err, tempPath, renameErr)
			}
			return
		}
		if removeErr := os.Remove(tempPath); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
			err = NewError(StatusIoError, fmt.Sprintf("Failed to remove temporary output: %v", removeErr))
		}
	}()

	newImage, err := filemap.CreateFromFile(tempFile, int(newSize))
	if err != nil {
		_ = tempFile.Close()
		return NewError(StatusFileWriteError, fmt.Sprintf("Failed to map new image: %v", err))
	}

	if code := applyBufferWithCheckedOldImage(oldImage.Data, reader, newImage.Data); code != StatusSuccess {
		_ = newImage.Close()
		return NewError(code, "ApplyBuffer failed")
	}
	if verifySHA256 {
		digest := sha256.Sum256(newImage.Data)
		if subtle.ConstantTimeCompare(digest[:], expectedSHA256[:]) != 1 {
			_ = newImage.Close()
			return NewError(StatusInvalidNewImage, "Reconstructed image SHA-256 does not match the trusted digest")
		}
	}
	if closeErr := newImage.Close(); closeErr != nil {
		return NewError(StatusIoError, fmt.Sprintf("Failed to close temporary output: %v", closeErr))
	}
	if renameErr := os.Rename(tempPath, newPath); renameErr != nil {
		return NewError(StatusFileWriteError, fmt.Sprintf("Failed to install reconstructed image: %v", renameErr))
	}
	removeTemp = false
	return nil
}

// GenerateFile creates a patch from two file-backed inputs. Patch bytes are
// streamed to a temporary file and atomically installed after a complete,
// durable write.
func GenerateFile(oldPath, newPath, patchPath string) (err error) {
	return GenerateFileWithOptions(oldPath, newPath, patchPath, GenerateFileOptions{})
}

// GenerateFileWithOptions creates a patch using file-backed inputs and a
// sequential output sink. Raw and imposed generation use the same output
// lifecycle as automatic matching.
func GenerateFileWithOptions(oldPath, newPath, patchPath string, options GenerateFileOptions) (err error) {
	if options.Raw && options.ImposedMatches != "" {
		return NewError(StatusInvalidParam, "Raw and imposed generation are mutually exclusive")
	}
	if filemap.SameFile(patchPath, oldPath) || filemap.SameFile(patchPath, newPath) {
		return NewError(StatusInvalidParam, "Output path must be different from input paths")
	}
	if err := validatePatchInputFileSize(oldPath, "old image"); err != nil {
		return err
	}
	if err := validatePatchInputFileSize(newPath, "new image"); err != nil {
		return err
	}
	oldImage, err := filemap.Open(oldPath)
	if err != nil {
		return NewError(StatusFileReadError, fmt.Sprintf("Failed to map old image: %v", err))
	}
	defer closeFileMapping(oldImage, &err)

	newImage, err := filemap.Open(newPath)
	if err != nil {
		return NewError(StatusFileReadError, fmt.Sprintf("Failed to map new image: %v", err))
	}
	defer closeFileMapping(newImage, &err)

	var patchWriter *patch.EnsemblePatchWriter
	if options.Raw || options.ImposedMatches != "" {
		patchWriter = patch.NewEnsemblePatchWriter(oldImage.Data, newImage.Data)
		var code StatusCode
		if options.Raw {
			code = GenerateBufferRaw(oldImage.Data, newImage.Data, patchWriter)
		} else {
			code = GenerateBufferImposed(oldImage.Data, newImage.Data, options.ImposedMatches, patchWriter)
		}
		if code != StatusSuccess {
			return NewError(code, "Failed to generate patch")
		}
	} else {
		patchWriter, err = generatePatchWriter(oldImage.Data, newImage.Data)
		if err != nil {
			return err
		}
	}
	return writePatchFile(patchPath, patchWriter, options.KeepPartialOutput)
}

var patchTempCounter atomic.Uint64

func validatePatchInputFileSize(path, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return NewError(StatusFileReadError, fmt.Sprintf("Failed to stat %s: %v", label, err))
	}
	if info.Size() < 0 || uint64(info.Size()) >= uint64(types.OffsetBound) {
		return NewError(StatusInvalidParam, fmt.Sprintf("%s exceeds the patch format's 32-bit size limit", label))
	}
	return nil
}

func createPatchTemp(path string) (*os.File, error) {
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	for {
		sequence := patchTempCounter.Add(1)
		tempPath := filepath.Join(directory, fmt.Sprintf(".%s.tmp-%d-%d", base, os.Getpid(), sequence))
		file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
		if os.IsExist(err) {
			continue
		}
		return file, err
	}
}

func writePatchFile(path string, patchWriter *patch.EnsemblePatchWriter, keepPartial bool) (err error) {
	file, createErr := createPatchTemp(path)
	if createErr != nil {
		return NewError(StatusFileWriteError, fmt.Sprintf("Failed to create temporary patch: %v", createErr))
	}
	tempPath := file.Name()
	removeTemp := true
	defer func() {
		if file != nil {
			if closeErr := file.Close(); closeErr != nil && err == nil {
				err = NewError(StatusIoError, fmt.Sprintf("Failed to close temporary patch: %v", closeErr))
			}
		}
		if !removeTemp {
			return
		}
		if keepPartial && err != nil {
			if renameErr := os.Rename(tempPath, path); renameErr != nil {
				err = fmt.Errorf("%w; failed to retain partial patch %q: %v", err, tempPath, renameErr)
			}
			return
		}
		if removeErr := os.Remove(tempPath); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
			err = NewError(StatusIoError, fmt.Sprintf("Failed to remove temporary patch: %v", removeErr))
		}
	}()

	sink := buffer.NewWriterSink(file)
	if !patchWriter.SerializeInto(sink) {
		if sink.Err() != nil {
			return NewError(StatusPatchWriteError, fmt.Sprintf("Failed to serialize patch: %v", sink.Err()))
		}
		return NewError(StatusPatchWriteError, "Failed to serialize patch")
	}
	expectedSize := int64(patchWriter.SerializedSize())
	if sink.Cursor() != expectedSize {
		return NewError(StatusPatchWriteError, fmt.Sprintf("Serialized patch size is %d, expected %d", sink.Cursor(), expectedSize))
	}
	if syncErr := file.Sync(); syncErr != nil {
		return NewError(StatusIoError, fmt.Sprintf("Failed to flush patch: %v", syncErr))
	}
	if closeErr := file.Close(); closeErr != nil {
		file = nil
		return NewError(StatusIoError, fmt.Sprintf("Failed to close patch: %v", closeErr))
	}
	file = nil
	if renameErr := os.Rename(tempPath, path); renameErr != nil {
		return NewError(StatusFileWriteError, fmt.Sprintf("Failed to install patch: %v", renameErr))
	}
	removeTemp = false
	return nil
}

func closeFileMapping(mapping *filemap.Mapping, returnErr *error) {
	if err := mapping.Close(); err != nil && *returnErr == nil {
		*returnErr = NewError(StatusIoError, fmt.Sprintf("Failed to close mapped file: %v", err))
	}
}

func maxIntValue() int {
	return int(^uint(0) >> 1)
}
