package types

import "fmt"

type Offset uint32
type RVA uint32

const (
	InvalidOffset Offset = 0xFFFFFFFF
	InvalidRVA    RVA    = 0xFFFFFFFF
	OffsetBound   Offset = 0xFFFFFFFF
	RVABound      RVA    = 0xFFFFFFFF
)

type Bitness uint8

const (
	Bit32 Bitness = 32
	Bit64 Bitness = 64
)

func (b Bitness) Width() uint32 {
	return uint32(b) / 8
}

type ExecutableType uint32

const (
	ExecutableTypeUnknown    ExecutableType = 0xFFFFFFFF
	ExecutableTypeNoOp       ExecutableType = 'N' | ('o' << 8) | ('O' << 16) | ('p' << 24)
	ExecutableTypeWin32X86   ExecutableType = 'P' | ('x' << 8) | ('8' << 16) | ('6' << 24)
	ExecutableTypeWin32X64   ExecutableType = 'P' | ('x' << 8) | ('6' << 16) | ('4' << 24)
	ExecutableTypeElfX86     ExecutableType = 'E' | ('x' << 8) | ('8' << 16) | ('6' << 24)
	ExecutableTypeElfX64     ExecutableType = 'E' | ('x' << 8) | ('6' << 16) | ('4' << 24)
	ExecutableTypeElfAArch32 ExecutableType = 'E' | ('A' << 8) | ('3' << 16) | ('2' << 24)
	ExecutableTypeElfAArch64 ExecutableType = 'E' | ('A' << 8) | ('6' << 16) | ('4' << 24)
	ExecutableTypeDex        ExecutableType = 'D' | ('E' << 8) | ('X' << 16) | (' ' << 24)
	ExecutableTypeZtf        ExecutableType = 'Z' | ('T' << 8) | ('F' << 16) | (' ' << 24)
)

func (t ExecutableType) String() string {
	switch t {
	case ExecutableTypeNoOp:
		return "NoOp"
	case ExecutableTypeWin32X86:
		return "Win32X86"
	case ExecutableTypeWin32X64:
		return "Win32X64"
	case ExecutableTypeElfX86:
		return "ElfX86"
	case ExecutableTypeElfX64:
		return "ElfX64"
	case ExecutableTypeElfAArch32:
		return "ElfAArch32"
	case ExecutableTypeElfAArch64:
		return "ElfAArch64"
	case ExecutableTypeDex:
		return "Dex"
	case ExecutableTypeZtf:
		return "Ztf"
	default:
		return fmt.Sprintf("ExecutableType(%d)", t)
	}
}

type TypeTag uint8
type PoolTag uint8

const (
	NoTypeTag TypeTag = 0xFF
	NoPoolTag PoolTag = 0xFF
)

type BufferRegion struct {
	Offset int
	Size   int
}

func (r BufferRegion) Hi() int {
	return r.Offset + r.Size
}

type Reference struct {
	Location Offset
	Target   Offset
}

type Equivalence struct {
	SrcOffset Offset
	DstOffset Offset
	Length    Offset
}

func (e Equivalence) SrcEnd() Offset {
	return e.SrcOffset + e.Length
}

func (e Equivalence) DstEnd() Offset {
	return e.DstOffset + e.Length
}

type EquivalenceCandidate struct {
	Eq         Equivalence
	Similarity float64
}

type Element struct {
	Region  BufferRegion
	ExeType ExecutableType
}

func (e Element) EndOffset() Offset {
	return Offset(e.Region.Hi())
}

type ElementMatch struct {
	OldElement Element
	NewElement Element
}

type Unit struct {
	OffsetBegin Offset
	OffsetSize  Offset
	RVABegin    RVA
	RVASize     RVA
}

func (u Unit) OffsetEnd() Offset { return u.OffsetBegin + u.OffsetSize }
func (u Unit) RVAEnd() RVA       { return u.RVABegin + u.RVASize }

func (u Unit) IsEmpty() bool {
	return u.RVASize == 0
}

func (u Unit) CoversOffset(offset Offset) bool {
	return offset >= u.OffsetBegin && (offset-u.OffsetBegin) < u.OffsetSize
}

func (u Unit) CoversRVA(rva RVA) bool {
	return rva >= u.RVABegin && (rva-u.RVABegin) < u.RVASize
}

func (u Unit) CoversDanglingRVA(rva RVA) bool {
	return u.CoversRVA(rva) && (rva-u.RVABegin) >= RVA(u.OffsetSize)
}

func (u Unit) OffsetToRVAUnsafe(offset Offset) RVA {
	return RVA(offset-u.OffsetBegin) + u.RVABegin
}

func (u Unit) RVAToOffsetUnsafe(rva RVA, fakeOffsetBegin Offset) Offset {
	delta := rva - u.RVABegin
	if delta < RVA(u.OffsetSize) {
		return u.OffsetBegin + Offset(delta)
	}
	return fakeOffsetBegin + Offset(rva)
}

func (u Unit) HasDanglingRVA() bool {
	return u.RVASize > RVA(u.OffsetSize)
}

type ReferenceTypeTraits struct {
	Width   Offset
	TypeTag TypeTag
	PoolTag PoolTag
}

type ReferenceReader interface {
	GetNext() (Reference, bool)
}

type ReferenceWriter interface {
	PutNext(ref Reference)
}
