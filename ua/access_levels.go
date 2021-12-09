// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// AccessLevels set for the AccessLevel attribute.
const (
	AccessLevelsNone           byte = 0x0
	AccessLevelsCurrentRead    byte = 0x1
	AccessLevelsCurrentWrite   byte = 0x2
	AccessLevelsHistoryRead    byte = 0x4
	AccessLevelsHistoryWrite   byte = 0x8
	AccessLevelsSemanticChange byte = 0x10
	AccessLevelsStatusWrite    byte = 0x20
	AccessLevelsTimestampWrite byte = 0x40
)
