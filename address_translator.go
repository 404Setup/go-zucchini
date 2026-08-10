package zucchini

import (
	"github.com/404Setup/go-zucchini/internal/disasm"
)

type AddressTranslatorStatus = disasm.AddressTranslatorStatus

const (
	AddressTranslatorSuccess                      = disasm.AddressTranslatorSuccess
	AddressTranslatorErrorOverflow                = disasm.AddressTranslatorErrorOverflow
	AddressTranslatorErrorBadOverlap              = disasm.AddressTranslatorErrorBadOverlap
	AddressTranslatorErrorBadOverlapDanglingRVA   = disasm.AddressTranslatorErrorBadOverlapDanglingRVA
	AddressTranslatorErrorFakeOffsetBeginTooLarge = disasm.AddressTranslatorErrorFakeOffsetBeginTooLarge
)

type AddressTranslator = disasm.AddressTranslatorStruct

func NewAddressTranslator() *AddressTranslator {
	return disasm.NewAddressTranslator()
}

type OffsetToRVACache = disasm.OffsetToRVACache

func NewOffsetToRVACache(translator *AddressTranslator) *OffsetToRVACache {
	return disasm.NewOffsetToRVACache(translator)
}

type RVAToOffsetCache = disasm.RVAToOffsetCache

func NewRVAToOffsetCache(translator *AddressTranslator) *RVAToOffsetCache {
	return disasm.NewRVAToOffsetCache(translator)
}
