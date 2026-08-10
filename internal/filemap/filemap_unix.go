//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package filemap

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type Mapping struct {
	Data     []byte
	file     *os.File
	writable bool
}

func Open(path string) (*Mapping, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() > int64(maxInt()) {
		file.Close()
		return nil, fmt.Errorf("file is too large to map: %d bytes", info.Size())
	}
	mapping := &Mapping{file: file}
	if info.Size() == 0 {
		return mapping, nil
	}
	mapping.Data, err = syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
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
	mapping := &Mapping{file: file, writable: true}
	if size == 0 {
		return mapping, nil
	}
	data, err := syscall.Mmap(int(file.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	mapping.Data = data
	return mapping, nil
}

func (m *Mapping) Close() error {
	if m == nil {
		return nil
	}
	var errs []error
	if m.Data != nil {
		errs = appendError(errs, syscall.Munmap(m.Data))
		m.Data = nil
	}
	if m.file != nil {
		if m.writable {
			errs = appendError(errs, m.file.Sync())
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
