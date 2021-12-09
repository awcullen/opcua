// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// MessageType indicate the kind of message.
const (
	MessageTypeHello        uint32 = 'H' | 'E'<<8 | 'L'<<16 | 'F'<<24
	MessageTypeAck          uint32 = 'A' | 'C'<<8 | 'K'<<16 | 'F'<<24
	MessageTypeError        uint32 = 'E' | 'R'<<8 | 'R'<<16 | 'F'<<24
	MessageTypeReverseHello uint32 = 'R' | 'H'<<8 | 'E'<<16 | 'F'<<24
	MessageTypeOpenFinal    uint32 = 'O' | 'P'<<8 | 'N'<<16 | 'F'<<24
	MessageTypeCloseFinal   uint32 = 'C' | 'L'<<8 | 'O'<<16 | 'F'<<24
	MessageTypeFinal        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'F'<<24
	MessageTypeChunk        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'C'<<24
	MessageTypeAbort        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'A'<<24
)
