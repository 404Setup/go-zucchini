package disasm

import (
	"encoding/binary"
	"slices"
	"sort"

	"github.com/404Setup/go-zucchini/internal/types"
)

type DisassemblerWin32 struct {
	image             []byte
	isX64             bool
	exeType           types.ExecutableType
	exeTypeString     string
	bitness           types.Bitness
	relocType         uint16
	imageBase         uint64
	sections          []ImageSectionHeader
	translator        AddressTranslator
	relocRVA          types.RVA
	relocSize         int
	relocRegion       types.BufferRegion
	relocBlockOffsets []types.Offset
	abs32Locations    []types.Offset
	rel32Locations    []types.Offset
	hasParsedRelocs   bool
	hasParsedAbs32    bool
	hasParsedRel32    bool
}

func QuickDetectWin32(image []byte) bool {
	dos, ok := ParseImageDOSHeader(image)
	if !ok || dos.EMagic != 0x5A4D {
		return false
	}
	lfanew := int(dos.ELfanew)
	if dos.ELfanew&7 != 0 || lfanew < 0x40 || lfanew > len(image)-4-20 {
		return false
	}
	if binary.LittleEndian.Uint32(image[lfanew:]) != 0x00004550 {
		return false
	}
	return true
}

func NewDisassemblerWin32X86(image []byte) (*DisassemblerWin32, bool) {
	d := &DisassemblerWin32{
		image:         image,
		isX64:         false,
		exeType:       types.ExecutableTypeWin32X86,
		exeTypeString: "Windows PE / x86",
		bitness:       types.Bit32,
		relocType:     3,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func NewDisassemblerWin32X64(image []byte) (*DisassemblerWin32, bool) {
	d := &DisassemblerWin32{
		image:         image,
		isX64:         true,
		exeType:       types.ExecutableTypeWin32X64,
		exeTypeString: "Windows PE / x64",
		bitness:       types.Bit64,
		relocType:     10,
	}
	if !d.Parse() {
		return nil, false
	}
	return d, true
}

func (d *DisassemblerWin32) SetTranslator(trans AddressTranslator) {
	d.translator = trans
}

func (d *DisassemblerWin32) GetExeType() types.ExecutableType {
	return d.exeType
}

func (d *DisassemblerWin32) GetExeTypeString() string {
	return d.exeTypeString
}

func (d *DisassemblerWin32) Image() []byte {
	return d.image
}

func (d *DisassemblerWin32) Size() int {
	return len(d.image)
}

func (d *DisassemblerWin32) Abs32Len() int {
	return len(d.abs32Locations)
}

func (d *DisassemblerWin32) Rel32Len() int {
	return len(d.rel32Locations)
}

func (d *DisassemblerWin32) NumEquivalenceIterations() int {
	return 2
}

func (d *DisassemblerWin32) Parse() bool {
	if !QuickDetectWin32(d.image) {
		return false
	}
	dos, _ := ParseImageDOSHeader(d.image)
	peOffset := int(dos.ELfanew)

	fileHeaderOffset := peOffset + 4
	machine := binary.LittleEndian.Uint16(d.image[fileHeaderOffset:])
	numSections := binary.LittleEndian.Uint16(d.image[fileHeaderOffset+2:])
	optHeaderSize := binary.LittleEndian.Uint16(d.image[fileHeaderOffset+16:])
	if (!d.isX64 && machine != ImageFileMachineI386) ||
		(d.isX64 && machine != ImageFileMachineAMD64) {
		return false
	}

	optHeaderOffset := fileHeaderOffset + 20
	dataDirBase := 96
	fullOptHeaderSize := 0xE0
	numberOfDirsOffset := 92
	if d.isX64 {
		dataDirBase = 112
		fullOptHeaderSize = 0xF0
		numberOfDirsOffset = 108
	}
	if int(optHeaderSize) != fullOptHeaderSize || optHeaderOffset > len(d.image)-fullOptHeaderSize {
		return false
	}

	magic := binary.LittleEndian.Uint16(d.image[optHeaderOffset:])
	if !d.isX64 && magic != 0x10B {
		return false
	}
	if d.isX64 && magic != 0x20B {
		return false
	}

	if !d.isX64 {
		d.imageBase = uint64(binary.LittleEndian.Uint32(d.image[optHeaderOffset+28:]))
	} else {
		d.imageBase = binary.LittleEndian.Uint64(d.image[optHeaderOffset+24:])
	}

	numDataDirs := binary.LittleEndian.Uint32(d.image[optHeaderOffset+numberOfDirsOffset:])
	dataDirSize := int(optHeaderSize) - dataDirBase
	if dataDirSize < 0 || dataDirSize%8 != 0 ||
		uint32(dataDirSize/8) != numDataDirs || numDataDirs > ImageNumberOfDirectoryEntries ||
		numDataDirs <= IndexOfBaseRelocationTable {
		return false
	}

	sizeOfImage := binary.LittleEndian.Uint32(d.image[optHeaderOffset+56:])
	if sizeOfImage >= uint32(types.RVABound) {
		return false
	}

	dirOffset := optHeaderOffset + dataDirBase
	relocDirOffset := dirOffset + IndexOfBaseRelocationTable*8
	rva := binary.LittleEndian.Uint32(d.image[relocDirOffset:])
	sz := binary.LittleEndian.Uint32(d.image[relocDirOffset+4:])
	if uint64(sz) > uint64(^uint(0)>>1) {
		return false
	}
	d.relocRVA = types.RVA(rva)
	d.relocSize = int(sz)

	secHeaderOffset := optHeaderOffset + int(optHeaderSize)
	sectionTableSize := int(numSections) * 0x28
	if secHeaderOffset > len(d.image)-sectionTableSize {
		return false
	}
	offsetBound := secHeaderOffset + sectionTableSize
	hasCodeSection := false
	for i := 0; i < int(numSections); i++ {
		secOff := secHeaderOffset + i*0x28
		var sec ImageSectionHeader
		copy(sec.Name[:], d.image[secOff:])
		sec.VirtualSize = binary.LittleEndian.Uint32(d.image[secOff+8:])
		sec.VirtualAddress = binary.LittleEndian.Uint32(d.image[secOff+12:])
		sec.SizeOfRawData = binary.LittleEndian.Uint32(d.image[secOff+16:])
		sec.PointerToRawData = binary.LittleEndian.Uint32(d.image[secOff+20:])
		sec.Characteristics = binary.LittleEndian.Uint32(d.image[secOff+36:])

		endOffset := uint64(sec.PointerToRawData) + uint64(sec.SizeOfRawData)
		if endOffset > uint64(len(d.image)) ||
			uint64(sec.VirtualAddress)+uint64(sec.VirtualSize) > uint64(sizeOfImage) {
			return false
		}
		if int(endOffset) > offsetBound {
			offsetBound = int(endOffset)
		}
		hasCodeSection = hasCodeSection || IsWin32CodeSection(sec)

		d.sections = append(d.sections, sec)
	}

	if offsetBound > len(d.image) || !hasCodeSection {
		return false
	}
	d.image = d.image[:offsetBound]

	var units []types.Unit
	for _, sec := range d.sections {
		units = append(units, types.Unit{
			OffsetBegin: types.Offset(sec.PointerToRawData),
			OffsetSize:  types.Offset(sec.SizeOfRawData),
			RVABegin:    types.RVA(sec.VirtualAddress),
			RVASize:     types.RVA(sec.VirtualSize),
		})
	}
	trans := NewAddressTranslator()
	if trans.Initialize(units) != AddressTranslatorSuccess {
		return false
	}
	d.translator = trans

	return true
}

func (d *DisassemblerWin32) MakeReferenceGroups() []ReferenceGroup {
	d.ensureParsed()
	return d.makeReferenceGroups()
}

// MakeReferenceGroupsForWriter initializes only relocation block metadata.
// abs32 and rel32 writers need the parsed PE translator, but not the expensive
// lists of reference locations in the destination image.
func (d *DisassemblerWin32) MakeReferenceGroupsForWriter() []ReferenceGroup {
	d.ParseAndStoreRelocBlocks()
	return d.makeReferenceGroups()
}

func (d *DisassemblerWin32) makeReferenceGroups() []ReferenceGroup {
	relocGroup := ReferenceGroup{
		Traits: types.ReferenceTypeTraits{
			Width:   2,
			TypeTag: types.TypeTag(0),
			PoolTag: types.PoolTag(0),
		},
		ReferenceCountHint: len(d.abs32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			if !d.ParseAndStoreRelocBlocks() {
				return NewEmptyReferenceReader()
			}
			rvaReader := NewRelocRvaReaderWin32(d.image, d.relocRegion, d.relocBlockOffsets, lower, upper)
			vaWidth := int(d.bitness.Width())
			var offsetBound types.Offset = 0
			if len(d.image) >= vaWidth {
				offsetBound = types.Offset(len(d.image) - vaWidth + 1)
			}
			return NewRelocReaderWin32(rvaReader, d.relocType, offsetBound, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			if !d.ParseAndStoreRelocBlocks() {
				return NewEmptyReferenceWriter()
			}
			return NewRelocWriterWin32(d.relocType, image, d.relocRegion, d.relocBlockOffsets, d.translator)
		},
	}

	abs32Group := ReferenceGroup{
		Traits: types.ReferenceTypeTraits{
			Width:   types.Offset(d.bitness.Width()),
			TypeTag: types.TypeTag(1),
			PoolTag: types.PoolTag(1),
		},
		ReferenceCountHint: len(d.abs32Locations),
		ReaderFactory: func(lower, upper types.Offset) types.ReferenceReader {
			addr := NewAbsoluteAddress(d.bitness, d.imageBase)
			extractor := NewAbs32RvaExtractorWin32(d.image, addr, d.abs32Locations, lower, upper)
			return NewAbs32ReaderWin32(extractor, d.translator)
		},
		WriterFactory: func(image []byte) types.ReferenceWriter {
			addr := NewAbsoluteAddress(d.bitness, d.imageBase)
			return NewAbs32WriterWin32(image, addr, d.translator)
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

func (d *DisassemblerWin32) ensureParsed() {
	d.ParseAndStoreRelocBlocks()
	d.ParseAndStoreAbs32()
	d.ParseAndStoreRel32()
}

func (d *DisassemblerWin32) ParseAndStoreRelocBlocks() bool {
	if d.hasParsedRelocs {
		return d.relocRegion.Size > 0
	}
	d.hasParsedRelocs = true
	if d.relocSize == 0 || d.translator == nil {
		return false
	}
	relocOffset := d.translator.RVAToOffset(d.relocRVA)
	if relocOffset == types.InvalidOffset {
		return false
	}
	if uint64(relocOffset)+uint64(d.relocSize) > uint64(len(d.image)) {
		return false
	}
	tempRegion := types.BufferRegion{Offset: int(relocOffset), Size: d.relocSize}
	if !FindRelocBlocks(d.image, tempRegion, &d.relocBlockOffsets) {
		return false
	}
	d.relocRegion = tempRegion
	return true
}

func (d *DisassemblerWin32) ParseAndStoreAbs32() bool {
	if d.hasParsedAbs32 {
		return true
	}
	d.hasParsedAbs32 = true

	if !d.ParseAndStoreRelocBlocks() {
		return true
	}
	vaWidth := int(d.bitness.Width())
	if len(d.image) < vaWidth {
		return true
	}
	offsetBound := types.Offset(len(d.image) - vaWidth + 1)
	rvaReader := NewRelocRvaReaderWin32(d.image, d.relocRegion, d.relocBlockOffsets, 0, types.Offset(len(d.image)))
	relocReader := NewRelocReaderWin32(rvaReader, d.relocType, offsetBound, d.translator)
	for {
		ref, ok := relocReader.GetNext()
		if !ok {
			break
		}
		d.abs32Locations = append(d.abs32Locations, ref.Target)
	}

	slices.Sort(d.abs32Locations)
	RemoveUntranslatableAbs32(d.image, d.bitness, d.imageBase, d.translator, &d.abs32Locations)
	RemoveOverlappingAbs32Locations(vaWidth, &d.abs32Locations)
	return true
}

func (d *DisassemblerWin32) ParseAndStoreRel32() {
	if d.hasParsedRel32 {
		return
	}
	d.hasParsedRel32 = true

	targetRvaChecker := NewRvaToOffsetCache(d.translator)
	vaWidth := int(d.bitness.Width())

	for _, section := range d.sections {
		if !IsWin32CodeSection(section) {
			continue
		}

		startRVA := types.RVA(section.VirtualAddress)
		endRVA := startRVA + types.RVA(section.VirtualSize)
		sizeToUse := min(section.VirtualSize, section.SizeOfRawData)
		if int(section.PointerToRawData)+int(sizeToUse) > len(d.image) {
			continue
		}

		region := types.BufferRegion{Offset: int(section.PointerToRawData), Size: int(sizeToUse)}
		gapFinder := NewAbs32GapFinder(d.image, region, d.abs32Locations, vaWidth)
		var relFinder *Rel32FinderIntel
		if d.isX64 {
			relFinder = NewRel32FinderX64(d.image, d.translator)
		} else {
			relFinder = NewRel32FinderX86(d.image, d.translator)
		}

		for gapFinder.FindNext() {
			relFinder.SetRegion(gapFinder.GetGap())
			for relFinder.FindNext() {
				rel32 := relFinder.GetRel32()
				if targetRvaChecker.IsValid(rel32.TargetRVA) &&
					(rel32.CanPointOutsideSection || (startRVA <= rel32.TargetRVA && rel32.TargetRVA < endRVA)) {
					relFinder.Accept()
					d.rel32Locations = append(d.rel32Locations, rel32.Location)
				}
			}
		}
	}

	slices.Sort(d.rel32Locations)
}

func IsWin32CodeSection(section ImageSectionHeader) bool {
	return section.Characteristics&CodeCharacteristics == CodeCharacteristics
}

type Rel32ReaderX86 struct {
	image      []byte
	translator AddressTranslator
	locations  []types.Offset
	curIdx     int
	hi         types.Offset
}

func NewRel32ReaderX86(image []byte, lo, hi types.Offset, locations []types.Offset, trans AddressTranslator) *Rel32ReaderX86 {
	curIdx := sort.Search(len(locations), func(i int) bool {
		return locations[i] >= lo
	})
	return &Rel32ReaderX86{
		image:      image,
		translator: trans,
		locations:  locations,
		curIdx:     curIdx,
		hi:         hi,
	}
}

func (r *Rel32ReaderX86) GetNext() (types.Reference, bool) {
	for r.curIdx < len(r.locations) && r.locations[r.curIdx] < r.hi {
		loc := r.locations[r.curIdx]
		r.curIdx++
		if int(loc)+4 > len(r.image) {
			continue
		}
		locRVA := r.translator.OffsetToRVA(loc)
		if locRVA == types.InvalidRVA {
			continue
		}
		disp := binary.LittleEndian.Uint32(r.image[loc:])
		targetRVA := locRVA + 4 + types.RVA(disp)
		targetOffset := r.translator.RVAToOffset(targetRVA)
		if targetOffset != types.InvalidOffset {
			return types.Reference{Location: loc, Target: targetOffset}, true
		}
	}
	return types.Reference{}, false
}

type rel32IntelWriterAdapter struct {
	image      []byte
	translator AddressTranslator
}

func (w *rel32IntelWriterAdapter) PutNext(ref types.Reference) {
	if int(ref.Location)+4 <= len(w.image) && w.translator != nil {
		rva := w.translator.OffsetToRVA(ref.Target)
		if rva != types.InvalidRVA {
			locRVA := w.translator.OffsetToRVA(ref.Location)
			disp := uint32(rva - (locRVA + 4))
			binary.LittleEndian.PutUint32(w.image[ref.Location:], disp)
		}
	}
}
