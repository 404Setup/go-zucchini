package disasm

import (
	"encoding/binary"
	"slices"

	"github.com/404Setup/go-zucchini/internal/types"
)

type DisassemblerElf struct {
	image            []byte
	is64             bool
	arch             uint16
	exeType          types.ExecutableType
	exeTypeString    string
	bitness          types.Bitness
	relType          uint32
	translator       AddressTranslator
	relocSectionDims []SectionDimensionsElf
	abs32Locations   []types.Offset
	rel32Locations   []types.Offset
	rel32Arm32       [5][]types.Offset
	rel32Arm64       [3][]types.Offset
	execSections     []elfSection
}

type elfSection struct {
	typ       uint32
	flags     uint64
	addr      uint64
	offset    uint64
	size      uint64
	entrySize uint64
}

const elfSizeBound = uint64(0x7FFF0000)

func QuickDetectElf(image []byte) bool {
	if len(image) < 16 {
		return false
	}
	return image[0] == 0x7F && image[1] == 'E' && image[2] == 'L' && image[3] == 'F'
}

func NewDisassemblerElfX86(image []byte) (*DisassemblerElf, bool) {
	d := &DisassemblerElf{
		image:         image,
		is64:          false,
		arch:          EM_386,
		exeType:       types.ExecutableTypeElfX86,
		exeTypeString: "ELF / x86",
		bitness:       types.Bit32,
		relType:       R_386_RELATIVE,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func NewDisassemblerElfX64(image []byte) (*DisassemblerElf, bool) {
	d := &DisassemblerElf{
		image:         image,
		is64:          true,
		arch:          EM_X86_64,
		exeType:       types.ExecutableTypeElfX64,
		exeTypeString: "ELF / x64",
		bitness:       types.Bit64,
		relType:       R_X86_64_RELATIVE,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func NewDisassemblerElfAArch64(image []byte) (*DisassemblerElf, bool) {
	d := &DisassemblerElf{
		image: image, is64: true, arch: EM_AARCH64,
		exeType: types.ExecutableTypeElfAArch64, exeTypeString: "ELF ARM64",
		bitness: types.Bit64, relType: R_AARCH64_RELATIVE,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func NewDisassemblerElfAArch32(image []byte) (*DisassemblerElf, bool) {
	d := &DisassemblerElf{
		image: image, is64: false, arch: EM_ARM,
		exeType: types.ExecutableTypeElfAArch32, exeTypeString: "ELF ARM",
		bitness: types.Bit32, relType: R_ARM_RELATIVE,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func (d *DisassemblerElf) SetTranslator(trans AddressTranslator) {
	d.translator = trans
}

func (d *DisassemblerElf) GetExeType() types.ExecutableType {
	return d.exeType
}

func (d *DisassemblerElf) GetExeTypeString() string {
	return d.exeTypeString
}

func (d *DisassemblerElf) Image() []byte {
	return d.image
}

func (d *DisassemblerElf) Size() int {
	return len(d.image)
}

func (d *DisassemblerElf) NumEquivalenceIterations() int {
	return 2
}

func (d *DisassemblerElf) Parse() bool {
	if !d.parseHeader() {
		return false
	}
	d.parseSections()
	return true
}

func (d *DisassemblerElf) parseHeader() bool {
	if !QuickDetectElf(d.image) || uint64(len(d.image)) >= uint64(types.OffsetBound) {
		return false
	}
	wantClass := byte(ELFCLASS32)
	sectionHeaderSize, programHeaderSize := 40, 32
	if d.is64 {
		wantClass = ELFCLASS64
		sectionHeaderSize, programHeaderSize = 64, 56
	}
	if d.image[EI_CLASS] != wantClass || d.image[EI_DATA] != 1 || d.image[EI_VERSION] != 1 {
		return false
	}

	var fileType, machine uint16
	var version uint32
	var sectionOffset, programOffset uint64
	var sectionCount, programCount, sectionNameIndex uint16
	var sectionEntrySize uint16
	if d.is64 {
		h, ok := ParseElf64Ehdr(d.image)
		if !ok {
			return false
		}
		fileType, machine, version = h.EType, h.EMachine, h.EVersion
		sectionOffset, programOffset = h.EShoff, h.EPhoff
		sectionCount, programCount, sectionNameIndex = h.EShnum, h.EPhnum, h.EShstrndx
		sectionEntrySize = h.EShentsize
	} else {
		h, ok := ParseElf32Ehdr(d.image)
		if !ok {
			return false
		}
		fileType, machine, version = h.EType, h.EMachine, h.EVersion
		sectionOffset, programOffset = uint64(h.EShoff), uint64(h.EPhoff)
		sectionCount, programCount, sectionNameIndex = h.EShnum, h.EPhnum, h.EShstrndx
		sectionEntrySize = h.EShentsize
	}
	if (fileType != ET_EXEC && fileType != ET_DYN) || machine != d.arch || version != 1 ||
		int(sectionEntrySize) != sectionHeaderSize {
		return false
	}
	sectionTableEnd, ok := boundedTableEnd(sectionOffset, uint64(sectionCount), uint64(sectionHeaderSize), len(d.image))
	if !ok {
		return false
	}
	programTableEnd, ok := boundedTableEnd(programOffset, uint64(programCount), uint64(programHeaderSize), len(d.image))
	if !ok || sectionNameIndex >= sectionCount {
		return false
	}

	sections := make([]elfSection, sectionCount)
	for i := range sections {
		off := int(sectionOffset) + i*sectionHeaderSize
		sections[i] = parseElfSection(d.image[off:off+sectionHeaderSize], d.is64)
	}
	nameSection := sections[sectionNameIndex]
	if nameSection.size > 0 {
		end, ok := boundedEnd(nameSection.offset, nameSection.size, uint64(len(d.image)))
		if !ok || d.image[end-1] != 0 {
			return false
		}
	}

	offsetBound := max(sectionTableEnd, programTableEnd)
	for i := 0; i < int(programCount); i++ {
		off := int(programOffset) + i*programHeaderSize
		segmentOffset, segmentSize := parseElfProgramRange(d.image[off:off+programHeaderSize], d.is64)
		end, ok := boundedEnd(segmentOffset, segmentSize, uint64(len(d.image)))
		if !ok {
			return false
		}
		offsetBound = max(offsetBound, end)
	}

	units := make([]types.Unit, 0, len(sections))
	for _, section := range sections {
		judgement := judgeElfSection(section, len(d.image))
		if judgement == 0 {
			return false
		}
		if judgement&2 != 0 {
			units = append(units, types.Unit{
				OffsetBegin: types.Offset(section.offset),
				OffsetSize:  types.Offset(section.size),
				RVABegin:    types.RVA(section.addr),
				RVASize:     types.RVA(section.size),
			})
		}
		if judgement&4 != 0 {
			offsetBound = max(offsetBound, section.offset+section.size)
		}
		if judgement&8 != 0 {
			if isRelocElfSection(section, d.is64) {
				d.relocSectionDims = append(d.relocSectionDims, SectionDimensionsElf{
					Region:    types.BufferRegion{Offset: int(section.offset), Size: int(section.size)},
					EntrySize: types.Offset(section.entrySize),
				})
			} else if section.typ == SHT_PROGBITS && section.flags&SHF_EXECINSTR != 0 {
				d.execSections = append(d.execSections, section)
			}
		}
	}
	translator := NewAddressTranslator()
	if translator.Initialize(units) != AddressTranslatorSuccess {
		return false
	}
	d.translator = translator
	slices.SortFunc(d.relocSectionDims, func(a, b SectionDimensionsElf) int { return a.Region.Offset - b.Region.Offset })
	slices.SortFunc(d.execSections, func(a, b elfSection) int {
		if a.offset < b.offset {
			return -1
		}
		if a.offset > b.offset {
			return 1
		}
		return 0
	})
	d.image = d.image[:int(offsetBound)]
	return true
}

func boundedTableEnd(offset, count, width uint64, imageSize int) (uint64, bool) {
	if count != 0 && width > (^uint64(0)-offset)/count {
		return 0, false
	}
	return boundedEnd(offset, count*width, uint64(imageSize))
}

func boundedEnd(offset, size, bound uint64) (uint64, bool) {
	if offset > bound || size > bound-offset {
		return 0, false
	}
	return offset + size, true
}

func parseElfSection(data []byte, is64 bool) elfSection {
	if !is64 {
		return elfSection{
			typ: binary.LittleEndian.Uint32(data[4:]), flags: uint64(binary.LittleEndian.Uint32(data[8:])),
			addr: uint64(binary.LittleEndian.Uint32(data[12:])), offset: uint64(binary.LittleEndian.Uint32(data[16:])),
			size: uint64(binary.LittleEndian.Uint32(data[20:])), entrySize: uint64(binary.LittleEndian.Uint32(data[36:])),
		}
	}
	return elfSection{
		typ: binary.LittleEndian.Uint32(data[4:]), flags: binary.LittleEndian.Uint64(data[8:]),
		addr: binary.LittleEndian.Uint64(data[16:]), offset: binary.LittleEndian.Uint64(data[24:]),
		size: binary.LittleEndian.Uint64(data[32:]), entrySize: binary.LittleEndian.Uint64(data[56:]),
	}
}

func parseElfProgramRange(data []byte, is64 bool) (uint64, uint64) {
	if !is64 {
		return uint64(binary.LittleEndian.Uint32(data[4:])), uint64(binary.LittleEndian.Uint32(data[16:]))
	}
	return binary.LittleEndian.Uint64(data[8:]), binary.LittleEndian.Uint64(data[32:])
}

func judgeElfSection(section elfSection, imageSize int) int {
	if section.addr > elfSizeBound || section.size > elfSizeBound-section.addr {
		return 0
	}
	offsetBound := uint64(imageSize)
	if section.typ == SHT_NOBITS {
		offsetBound = elfSizeBound
	}
	if section.offset > offsetBound || section.size > offsetBound-section.offset {
		return 0
	}
	if section.size == 0 || section.addr == 0 {
		return 1
	}
	if section.typ == SHT_NOBITS {
		if section.flags&SHF_TLS != 0 {
			return 1
		}
		return 1 | 2
	}
	return 1 | 2 | 4 | 8
}

func isRelocElfSection(section elfSection, is64 bool) bool {
	if section.typ == SHT_REL {
		if is64 {
			return section.entrySize == 16
		}
		return section.entrySize == 8
	}
	if section.typ == SHT_RELA {
		if is64 {
			return section.entrySize == 24
		}
		return section.entrySize == 12
	}
	return false
}

func (d *DisassemblerElf) parseSections() {
	relocs := NewRelocReaderElf(d.image, d.bitness, d.relocSectionDims, d.relType, 0, types.Offset(len(d.image)), d.translator)
	for {
		ref, ok := relocs.GetNext()
		if !ok {
			break
		}
		d.abs32Locations = append(d.abs32Locations, ref.Target)
	}
	slices.Sort(d.abs32Locations)
	RemoveUntranslatableAbs32(d.image, d.bitness, 0, d.translator, &d.abs32Locations)
	RemoveOverlappingAbs32Locations(int(d.bitness.Width()), &d.abs32Locations)

	if d.arch == EM_ARM {
		d.rel32Arm32 = findArm32Rel32(d.image, d.translator, d.execSections, d.abs32Locations, int(d.bitness.Width()))
		return
	}
	if d.arch == EM_AARCH64 {
		d.rel32Arm64 = findArm64Rel32(d.image, d.translator, d.execSections, d.abs32Locations, int(d.bitness.Width()))
		return
	}

	checker := NewRvaToOffsetCache(d.translator)
	for _, section := range d.execSections {
		gapFinder := NewAbs32GapFinder(d.image, types.BufferRegion{Offset: int(section.offset), Size: int(section.size)}, d.abs32Locations, int(d.bitness.Width()))
		var finder *Rel32FinderIntel
		if d.is64 {
			finder = NewRel32FinderX64(d.image, d.translator)
		} else {
			finder = NewRel32FinderX86(d.image, d.translator)
		}
		for gapFinder.FindNext() {
			finder.SetRegion(gapFinder.GetGap())
			for finder.FindNext() {
				rel := finder.GetRel32()
				inside := uint64(rel.TargetRVA) >= section.addr && uint64(rel.TargetRVA) < section.addr+section.size
				if checker.IsValid(rel.TargetRVA) && (rel.CanPointOutsideSection || inside) {
					finder.Accept()
					d.rel32Locations = append(d.rel32Locations, rel.Location)
				}
			}
		}
	}
	slices.Sort(d.rel32Locations)
}

func (d *DisassemblerElf) MakeReferenceGroups() []ReferenceGroup {
	if d.arch == EM_ARM {
		return d.makeReferenceGroupsArm32()
	}
	if d.arch == EM_AARCH64 {
		return d.makeReferenceGroupsArm64()
	}
	relocationCount := 0
	for _, dims := range d.relocSectionDims {
		if dims.EntrySize > 0 {
			relocationCount += dims.Region.Size / int(dims.EntrySize)
		}
	}
	relocGroup := ReferenceGroup{
		Traits: types.ReferenceTypeTraits{
			Width:   types.Offset(d.bitness.Width()),
			TypeTag: types.TypeTag(0),
			PoolTag: types.PoolTag(0),
		},
		ReferenceCountHint: relocationCount,
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewRelocReaderElf(d.image, d.bitness, d.relocSectionDims, d.relType, lower, upper, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return NewRelocWriterElf(image, d.bitness, d.translator)
		},
	}

	abs32Group := ReferenceGroup{
		Traits:             types.ReferenceTypeTraits{Width: types.Offset(d.bitness.Width()), TypeTag: 1, PoolTag: 1},
		ReferenceCountHint: len(d.abs32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			extractor := NewAbs32RvaExtractorWin32(d.image, NewAbsoluteAddress(d.bitness, 0), d.abs32Locations, lower, upper)
			return NewAbs32ReaderWin32(extractor, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return NewAbs32WriterWin32(image, NewAbsoluteAddress(d.bitness, 0), d.translator)
		},
	}

	rel32Group := ReferenceGroup{
		Traits: types.ReferenceTypeTraits{
			Width:   4,
			TypeTag: types.TypeTag(2),
			PoolTag: types.PoolTag(2),
		},
		ReferenceCountHint: len(d.rel32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewRel32ReaderX86(d.image, lower, upper, d.rel32Locations, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return &rel32IntelWriterAdapter{image: image, translator: d.translator}
		},
	}

	return []ReferenceGroup{relocGroup, abs32Group, rel32Group}
}

func (d *DisassemblerElf) makeReferenceGroupsArm32() []ReferenceGroup {
	groups := make([]ReferenceGroup, 0, 7)
	groups = append(groups, ReferenceGroup{
		Traits: types.ReferenceTypeTraits{Width: 4, TypeTag: 0, PoolTag: 0},
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewRelocReaderElf(d.image, d.bitness, d.relocSectionDims, d.relType, lower, upper, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return NewRelocWriterElf(image, d.bitness, d.translator)
		},
	})
	groups = append(groups, ReferenceGroup{
		Traits:             types.ReferenceTypeTraits{Width: 4, TypeTag: 1, PoolTag: 1},
		ReferenceCountHint: len(d.abs32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewAbs32ReaderWin32(NewAbs32RvaExtractorWin32(d.image, NewAbsoluteAddress(d.bitness, 0), d.abs32Locations, lower, upper), d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return NewAbs32WriterWin32(image, NewAbsoluteAddress(d.bitness, 0), d.translator)
		},
	})
	for kind := arm32A24; kind <= arm32T24; kind++ {
		kind := kind
		locations := d.rel32Arm32[kind]
		groups = append(groups, ReferenceGroup{
			Traits:             types.ReferenceTypeTraits{Width: types.Offset(arm32Width(kind)), TypeTag: types.TypeTag(2 + kind), PoolTag: 2},
			ReferenceCountHint: len(locations),
			ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
				return newRel32ReaderArm32(kind, d.translator, d.image, locations, lower, upper)
			},
			WriterFactory: func(image []byte) types.ReferenceWriter {
				return &rel32WriterArm32{kind: kind, translator: d.translator, image: image}
			},
			MixerFactory: func(oldImage, newImage []byte) ReferenceMixer {
				return &rel32MixerArm32{kind: kind, oldImage: oldImage, newImage: newImage}
			},
		})
	}
	return groups
}

func (d *DisassemblerElf) makeReferenceGroupsArm64() []ReferenceGroup {
	groups := make([]ReferenceGroup, 0, 5)
	groups = append(groups, ReferenceGroup{
		Traits: types.ReferenceTypeTraits{Width: 8, TypeTag: 0, PoolTag: 0},
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewRelocReaderElf(d.image, d.bitness, d.relocSectionDims, d.relType, lower, upper, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter { return NewRelocWriterElf(image, d.bitness, d.translator) },
	})
	groups = append(groups, ReferenceGroup{
		Traits:             types.ReferenceTypeTraits{Width: 8, TypeTag: 1, PoolTag: 1},
		ReferenceCountHint: len(d.abs32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			return NewAbs32ReaderWin32(NewAbs32RvaExtractorWin32(d.image, NewAbsoluteAddress(d.bitness, 0), d.abs32Locations, lower, upper), d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			return NewAbs32WriterWin32(image, NewAbsoluteAddress(d.bitness, 0), d.translator)
		},
	})
	for kind := arm64Immd14; kind <= arm64Immd26; kind++ {
		kind := kind
		locations := d.rel32Arm64[kind]
		groups = append(groups, ReferenceGroup{
			Traits:             types.ReferenceTypeTraits{Width: 4, TypeTag: types.TypeTag(2 + kind), PoolTag: 2},
			ReferenceCountHint: len(locations),
			ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
				return newRel32ReaderArm64(kind, d.translator, d.image, locations, lower, upper)
			},
			WriterFactory: func(image []byte) types.ReferenceWriter {
				return &rel32WriterArm64{kind: kind, translator: d.translator, image: image}
			},
			MixerFactory: func(oldImage, newImage []byte) ReferenceMixer {
				return &rel32MixerArm64{kind: kind, oldImage: oldImage, newImage: newImage}
			},
		})
	}
	return groups
}
