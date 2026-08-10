//go:build windows && !zucchini_mmap

package filemap

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Mapping uses ordinary file I/O in default Windows builds. Excluding this
// package's unsafe writable-mapping backend makes its file behavior easier for
// users and security products to inspect.
type Mapping struct {
	Data     []byte
	file     *os.File
	writable bool
}

func Open(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &Mapping{Data: data}, nil
}

func Create(path string, size int) (*Mapping, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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
		return nil, fmt.Errorf("nil output file")
	}
	if size < 0 {
		return nil, fmt.Errorf("negative output size %d", size)
	}
	if err := file.Truncate(0); err != nil {
		return nil, err
	}
	return &Mapping{Data: make([]byte, size), file: file, writable: true}, nil
}

func (m *Mapping) Close() error {
	if m == nil {
		return nil
	}
	var errs []error
	if m.file != nil {
		if m.writable {
			if err := writeAll(m.file, m.Data); err != nil {
				errs = append(errs, err)
			} else if err := m.file.Sync(); err != nil {
				errs = append(errs, err)
			}
		}
		if err := m.file.Close(); err != nil {
			errs = append(errs, err)
		}
		m.file = nil
	}
	m.Data = nil
	return errors.Join(errs...)
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
