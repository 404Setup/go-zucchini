//go:build windows && zucchini_mmap

package filemap

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

type Mapping struct {
	Data     []byte
	file     *os.File
	handle   syscall.Handle
	address  uintptr
	writable bool
}

func Open(path string) (*Mapping, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	mapping, err := mapFile(file, 0, false)
	if err != nil {
		file.Close()
		return nil, err
	}
	return mapping, nil
}

func Create(path string, size int) (*Mapping, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	mapping, err := CreateFromFile(file, size)
	if err != nil {
		file.Close()
		return nil, err
	}
	return mapping, nil
}

// CreateFromFile takes ownership of file on success. The caller retains
// ownership on failure.
func CreateFromFile(file *os.File, size int) (*Mapping, error) {
	if file == nil {
		return nil, fmt.Errorf("nil mapping file")
	}
	if size < 0 {
		return nil, fmt.Errorf("negative mapping size %d", size)
	}
	if err := file.Truncate(int64(size)); err != nil {
		return nil, err
	}
	mapping, err := mapFile(file, size, true)
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

func mapFile(file *os.File, knownSize int, writable bool) (*Mapping, error) {
	size := knownSize
	if !writable {
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if info.Size() > int64(maxInt()) {
			return nil, fmt.Errorf("file is too large to map: %d bytes", info.Size())
		}
		size = int(info.Size())
	}
	mapping := &Mapping{file: file, writable: writable}
	if size == 0 {
		return mapping, nil
	}

	protection := uint32(syscall.PAGE_READONLY)
	access := uint32(syscall.FILE_MAP_READ)
	if writable {
		protection = syscall.PAGE_READWRITE
		access = syscall.FILE_MAP_READ | syscall.FILE_MAP_WRITE
	}
	handle, err := syscall.CreateFileMapping(syscall.Handle(file.Fd()), nil, protection, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	address, err := syscall.MapViewOfFile(handle, access, 0, 0, uintptr(size))
	if err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}
	mapping.handle = handle
	mapping.address = address
	mapping.Data = sliceFromAddress(address, size)
	return mapping, nil
}

func sliceFromAddress(address uintptr, size int) []byte {
	var data []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	header.Data = address
	header.Len = size
	header.Cap = size
	return data
}

func (m *Mapping) Close() error {
	if m == nil {
		return nil
	}
	var errs []error
	if m.address != 0 {
		if m.writable {
			errs = appendError(errs, syscall.FlushViewOfFile(m.address, uintptr(len(m.Data))))
		}
		errs = appendError(errs, syscall.UnmapViewOfFile(m.address))
		m.address = 0
		m.Data = nil
	}
	if m.handle != 0 {
		errs = appendError(errs, syscall.CloseHandle(m.handle))
		m.handle = 0
	}
	if m.file != nil {
		if m.writable {
			errs = appendError(errs, syscall.FlushFileBuffers(syscall.Handle(m.file.Fd())))
		}
		errs = appendError(errs, m.file.Close())
		m.file = nil
	}
	return errors.Join(errs...)
}

func appendError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
