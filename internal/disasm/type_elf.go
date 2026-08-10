package disasm

import "encoding/binary"

const (
	EI_MAG0       = 0
	EI_MAG1       = 1
	EI_MAG2       = 2
	EI_MAG3       = 3
	EI_CLASS      = 4
	EI_DATA       = 5
	EI_VERSION    = 6
	EI_OSABI      = 7
	EI_ABIVERSION = 8
	EI_PAD        = 9
	EI_NIDENT     = 16

	ELFCLASSNONE = 0
	ELFCLASS32   = 1
	ELFCLASS64   = 2

	ET_NONE = 0
	ET_REL  = 1
	ET_EXEC = 2
	ET_DYN  = 3
	ET_CORE = 4

	EM_NONE    = 0
	EM_386     = 3
	EM_ARM     = 40
	EM_X86_64  = 62
	EM_AARCH64 = 183

	SHT_NULL       = 0
	SHT_PROGBITS   = 1
	SHT_SYMTAB     = 2
	SHT_STRTAB     = 3
	SHT_RELA       = 4
	SHT_HASH       = 5
	SHT_DYNAMIC    = 6
	SHT_NOTE       = 7
	SHT_NOBITS     = 8
	SHT_REL        = 9
	SHT_SHLIB      = 10
	SHT_DYNSYM     = 11
	SHT_INIT_ARRAY = 14
	SHT_FINI_ARRAY = 15

	SHF_WRITE     = 1 << 0
	SHF_ALLOC     = 1 << 1
	SHF_EXECINSTR = 1 << 2
	SHF_TLS       = 1 << 10

	PT_NULL    = 0
	PT_LOAD    = 1
	PT_DYNAMIC = 2
	PT_INTERP  = 3
	PT_NOTE    = 4
	PT_SHLIB   = 5
	PT_PHDR    = 6

	R_386_NONE     = 0
	R_386_32       = 1
	R_386_PC32     = 2
	R_386_GLOB_DAT = 6
	R_386_JMP_SLOT = 7
	R_386_RELATIVE = 8

	R_X86_64_NONE      = 0
	R_X86_64_64        = 1
	R_X86_64_PC32      = 2
	R_X86_64_GLOB_DAT  = 6
	R_X86_64_JUMP_SLOT = 7
	R_X86_64_RELATIVE  = 8
	R_X86_64_32        = 10

	R_ARM_RELATIVE = 23

	R_AARCH64_GLOB_DAT  = 0x401
	R_AARCH64_JUMP_SLOT = 0x402
	R_AARCH64_RELATIVE  = 0x403
)

type Elf32_Ehdr struct {
	EIdent     [16]byte
	EType      uint16
	EMachine   uint16
	EVersion   uint32
	EEntry     uint32
	EPhoff     uint32
	EShoff     uint32
	EFlags     uint32
	EEhsize    uint16
	EPhentsize uint16
	EPhnum     uint16
	EShentsize uint16
	EShnum     uint16
	EShstrndx  uint16
}

type Elf64_Ehdr struct {
	EIdent     [16]byte
	EType      uint16
	EMachine   uint16
	EVersion   uint32
	EEntry     uint64
	EPhoff     uint64
	EShoff     uint64
	EFlags     uint32
	EEhsize    uint16
	EPhentsize uint16
	EPhnum     uint16
	EShentsize uint16
	EShnum     uint16
	EShstrndx  uint16
}

type Elf32_Shdr struct {
	ShName      uint32
	ShType      uint32
	ShFlags     uint32
	ShAddr      uint32
	ShOffset    uint32
	ShSize      uint32
	ShLink      uint32
	ShInfo      uint32
	ShAddralign uint32
	ShEntsize   uint32
}

type Elf64_Shdr struct {
	ShName      uint32
	ShType      uint32
	ShFlags     uint64
	ShAddr      uint64
	ShOffset    uint64
	ShSize      uint64
	ShLink      uint32
	ShInfo      uint32
	ShAddralign uint64
	ShEntsize   uint64
}

type Elf32_Phdr struct {
	PType   uint32
	POffset uint32
	PVaddr  uint32
	PPaddr  uint32
	PFilesz uint32
	PMemsz  uint32
	PFlags  uint32
	PAlign  uint32
}

type Elf64_Phdr struct {
	PType   uint32
	PFlags  uint32
	POffset uint64
	PVaddr  uint64
	PPaddr  uint64
	PFilesz uint64
	PMemsz  uint64
	PAlign  uint64
}

type Elf32_Rel struct {
	ROffset uint32
	RInfo   uint32
}

type Elf64_Rel struct {
	ROffset uint64
	RInfo   uint64
}

type Elf32_Rela struct {
	ROffset uint32
	RInfo   uint32
	RAddend int32
}

type Elf64_Rela struct {
	ROffset uint64
	RInfo   uint64
	RAddend int64
}

func ParseElf32Ehdr(buf []byte) (*Elf32_Ehdr, bool) {
	if len(buf) < 52 {
		return nil, false
	}
	h := &Elf32_Ehdr{}
	copy(h.EIdent[:], buf[:16])
	h.EType = binary.LittleEndian.Uint16(buf[16:])
	h.EMachine = binary.LittleEndian.Uint16(buf[18:])
	h.EVersion = binary.LittleEndian.Uint32(buf[20:])
	h.EEntry = binary.LittleEndian.Uint32(buf[24:])
	h.EPhoff = binary.LittleEndian.Uint32(buf[28:])
	h.EShoff = binary.LittleEndian.Uint32(buf[32:])
	h.EFlags = binary.LittleEndian.Uint32(buf[36:])
	h.EEhsize = binary.LittleEndian.Uint16(buf[40:])
	h.EPhentsize = binary.LittleEndian.Uint16(buf[42:])
	h.EPhnum = binary.LittleEndian.Uint16(buf[44:])
	h.EShentsize = binary.LittleEndian.Uint16(buf[46:])
	h.EShnum = binary.LittleEndian.Uint16(buf[48:])
	h.EShstrndx = binary.LittleEndian.Uint16(buf[50:])
	return h, true
}

func ParseElf64Ehdr(buf []byte) (*Elf64_Ehdr, bool) {
	if len(buf) < 64 {
		return nil, false
	}
	h := &Elf64_Ehdr{}
	copy(h.EIdent[:], buf[:16])
	h.EType = binary.LittleEndian.Uint16(buf[16:])
	h.EMachine = binary.LittleEndian.Uint16(buf[18:])
	h.EVersion = binary.LittleEndian.Uint32(buf[20:])
	h.EEntry = binary.LittleEndian.Uint64(buf[24:])
	h.EPhoff = binary.LittleEndian.Uint64(buf[32:])
	h.EShoff = binary.LittleEndian.Uint64(buf[40:])
	h.EFlags = binary.LittleEndian.Uint32(buf[48:])
	h.EEhsize = binary.LittleEndian.Uint16(buf[52:])
	h.EPhentsize = binary.LittleEndian.Uint16(buf[54:])
	h.EPhnum = binary.LittleEndian.Uint16(buf[56:])
	h.EShentsize = binary.LittleEndian.Uint16(buf[58:])
	h.EShnum = binary.LittleEndian.Uint16(buf[60:])
	h.EShstrndx = binary.LittleEndian.Uint16(buf[62:])
	return h, true
}
