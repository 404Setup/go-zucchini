package zucchini

import (
	"github.com/404Setup/go-zucchini/internal/types"
)

type Offset = types.Offset
type RVA = types.RVA

const (
	InvalidOffset = types.InvalidOffset
	InvalidRVA    = types.InvalidRVA
	OffsetBound   = types.OffsetBound
	RVABound      = types.RVABound
)

type Bitness = types.Bitness

const (
	Bit32 = types.Bit32
	Bit64 = types.Bit64
)

type ExecutableType = types.ExecutableType

const (
	ExecutableTypeNoOp       = types.ExecutableTypeNoOp
	ExecutableTypeWin32X86   = types.ExecutableTypeWin32X86
	ExecutableTypeWin32X64   = types.ExecutableTypeWin32X64
	ExecutableTypeElfX86     = types.ExecutableTypeElfX86
	ExecutableTypeElfX64     = types.ExecutableTypeElfX64
	ExecutableTypeElfAArch32 = types.ExecutableTypeElfAArch32
	ExecutableTypeElfAArch64 = types.ExecutableTypeElfAArch64
	ExecutableTypeDex        = types.ExecutableTypeDex
	ExecutableTypeZtf        = types.ExecutableTypeZtf
)

type TypeTag = types.TypeTag
type PoolTag = types.PoolTag

const (
	NoTypeTag = types.NoTypeTag
	NoPoolTag = types.NoPoolTag
)

type BufferRegion = types.BufferRegion
type Reference = types.Reference
type Equivalence = types.Equivalence
type EquivalenceCandidate = types.EquivalenceCandidate
type Element = types.Element
type ElementMatch = types.ElementMatch
type Unit = types.Unit
type ReferenceTypeTraits = types.ReferenceTypeTraits
type ReferenceReader = types.ReferenceReader
type ReferenceWriter = types.ReferenceWriter
