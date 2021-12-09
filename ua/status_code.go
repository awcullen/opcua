// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// StatusCode is the result of the service call.
type StatusCode uint32

// IsGood returns true if the StatusCode is good.
func (c StatusCode) IsGood() bool {
	return (uint32(c) & SeverityMask) == SeverityGood
}

// IsBad returns true if the StatusCode is bad.
func (c StatusCode) IsBad() bool {
	return (uint32(c) & SeverityMask) == SeverityBad
}

// IsUncertain returns true if the StatusCode is uncertain.
func (c StatusCode) IsUncertain() bool {
	return (uint32(c) & SeverityMask) == SeverityUncertain
}

// IsStructureChanged returns true if the structure is changed.
func (c StatusCode) IsStructureChanged() bool {
	return (uint32(c) & StructureChanged) == StructureChanged
}

// IsSemanticsChanged returns true if the semantics is changed.
func (c StatusCode) IsSemanticsChanged() bool {
	return (uint32(c) & SemanticsChanged) == SemanticsChanged
}

// IsOverflow returns true if the data value has exceeded the limits of the data type.
func (c StatusCode) IsOverflow() bool {
	return ((uint32(c) & InfoTypeMask) == InfoTypeDataValue) && ((uint32(c) & Overflow) == Overflow)
}

const (
	// Good - The operation completed successfully.
	Good StatusCode = 0x00000000
	// SeverityMask - .
	SeverityMask uint32 = 0xC0000000
	// SeverityGood - .
	SeverityGood uint32 = 0x00000000
	// SeverityUncertain - .
	SeverityUncertain uint32 = 0x40000000
	// SeverityBad - .
	SeverityBad uint32 = 0x80000000
	// SubCodeMask - .
	SubCodeMask uint32 = 0x0FFF0000
	// StructureChanged - .
	StructureChanged uint32 = 0x00008000
	// SemanticsChanged - .
	SemanticsChanged uint32 = 0x00004000
	// InfoTypeMask - .
	InfoTypeMask uint32 = 0x00000C00
	// InfoTypeDataValue - .
	InfoTypeDataValue uint32 = 0x00000400
	// InfoBitsMask - .
	InfoBitsMask uint32 = 0x000003FF
	// LimitBitsMask - .
	LimitBitsMask uint32 = 0x00000300
	// LimitBitsNone - .
	LimitBitsNone uint32 = 0x00000000
	// LimitBitsLow - .
	LimitBitsLow uint32 = 0x00000100
	// LimitBitsHigh - .
	LimitBitsHigh uint32 = 0x00000200
	// LimitBitsConstant - .
	LimitBitsConstant uint32 = 0x00000300
	// Overflow - .
	Overflow uint32 = 0x00000080
	// HistorianBitsMask - the mask of bits that pertain to the Historian.
	HistorianBitsMask uint32 = 0x0000001F
	// HistorianBitsCalculated - A data value which was calculated.
	HistorianBitsCalculated uint32 = 0x00000001
	// HistorianBitsInterpolated - A data value which was interpolated.
	HistorianBitsInterpolated uint32 = 0x00000010
	// HistorianBitsPartial - A data value which was calculated with an incomplete interval.
	HistorianBitsPartial uint32 = 0x00000100
)
