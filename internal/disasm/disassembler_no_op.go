package disasm

import (
	"github.com/404Setup/go-zucchini/internal/types"
)

type DisassemblerNoOp struct {
	image []byte
}

func NewDisassemblerNoOp(image []byte) *DisassemblerNoOp {
	return &DisassemblerNoOp{image: image}
}

func (d *DisassemblerNoOp) GetExeType() types.ExecutableType {
	return types.ExecutableTypeNoOp
}

func (d *DisassemblerNoOp) GetExeTypeString() string {
	return "NoOp"
}

func (d *DisassemblerNoOp) Image() []byte {
	return d.image
}

func (d *DisassemblerNoOp) Size() int {
	return len(d.image)
}

func (d *DisassemblerNoOp) NumEquivalenceIterations() int {
	return 1
}

func (d *DisassemblerNoOp) Parse() bool {
	return true
}

func (d *DisassemblerNoOp) MakeReferenceGroups() []ReferenceGroup {
	return nil
}
