package matcher

import (
	"github.com/404Setup/go-zucchini/internal/disasm"
	"github.com/404Setup/go-zucchini/internal/types"
)

const MinProgramSize = 16

func MakeDisassemblerWithoutFallback(image []byte) disasm.Disassembler {
	if disasm.QuickDetectWin32(image) {
		if d, ok := disasm.NewDisassemblerWin32X86(image); ok && d.Size() >= MinProgramSize {
			return d
		}
		if d, ok := disasm.NewDisassemblerWin32X64(image); ok && d.Size() >= MinProgramSize {
			return d
		}
	}
	if disasm.QuickDetectElf(image) {
		if d, ok := disasm.NewDisassemblerElfX86(image); ok && d.Size() >= MinProgramSize {
			return d
		}
		if d, ok := disasm.NewDisassemblerElfX64(image); ok && d.Size() >= MinProgramSize {
			return d
		}
		if d, ok := disasm.NewDisassemblerElfAArch32(image); ok && d.Size() >= MinProgramSize {
			return d
		}
		if d, ok := disasm.NewDisassemblerElfAArch64(image); ok && d.Size() >= MinProgramSize {
			return d
		}
	}
	return nil
}

func MakeDisassemblerOfType(image []byte, exeType types.ExecutableType) disasm.Disassembler {
	switch exeType {
	case types.ExecutableTypeWin32X86:
		if d, ok := disasm.NewDisassemblerWin32X86(image); ok {
			return d
		}
	case types.ExecutableTypeWin32X64:
		if d, ok := disasm.NewDisassemblerWin32X64(image); ok {
			return d
		}
	case types.ExecutableTypeElfX86:
		if d, ok := disasm.NewDisassemblerElfX86(image); ok {
			return d
		}
	case types.ExecutableTypeElfX64:
		if d, ok := disasm.NewDisassemblerElfX64(image); ok {
			return d
		}
	case types.ExecutableTypeElfAArch32:
		if d, ok := disasm.NewDisassemblerElfAArch32(image); ok {
			return d
		}
	case types.ExecutableTypeElfAArch64:
		if d, ok := disasm.NewDisassemblerElfAArch64(image); ok {
			return d
		}
	case types.ExecutableTypeNoOp:
		return disasm.NewDisassemblerNoOp(image)
	}
	return nil
}

func DetectElementFromDisassembler(image []byte) (types.Element, bool) {
	d := MakeDisassemblerWithoutFallback(image)
	if d != nil {
		return types.Element{
			Region:  types.BufferRegion{Offset: 0, Size: d.Size()},
			ExeType: d.GetExeType(),
		}, true
	}
	return types.Element{}, false
}

type ElementDetector func(image []byte) (types.Element, bool)

type ElementFinder struct {
	image    []byte
	detector ElementDetector
	pos      int
}

func NewElementFinder(image []byte, detector ElementDetector) *ElementFinder {
	if detector == nil {
		detector = DetectElementFromDisassembler
	}
	return &ElementFinder{
		image:    image,
		detector: detector,
		pos:      0,
	}
}

func (f *ElementFinder) GetNext() (types.Element, bool) {
	for f.pos < len(f.image) {
		elem, ok := f.detector(f.image[f.pos:])
		if ok {
			elem.Region.Offset += f.pos
			f.pos = elem.Region.Hi()
			return elem, true
		}
		f.pos++
	}
	return types.Element{}, false
}
