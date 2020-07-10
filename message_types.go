// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

// messageTypes indicate the kind of message.
const (
	messageTypeHello        uint32 = 'H' | 'E'<<8 | 'L'<<16 | 'F'<<24
	messageTypeAck          uint32 = 'A' | 'C'<<8 | 'K'<<16 | 'F'<<24
	messageTypeError        uint32 = 'E' | 'R'<<8 | 'R'<<16 | 'F'<<24
	messageTypeReverseHello uint32 = 'R' | 'H'<<8 | 'E'<<16 | 'F'<<24
	messageTypeOpenFinal    uint32 = 'O' | 'P'<<8 | 'N'<<16 | 'F'<<24
	messageTypeCloseFinal   uint32 = 'C' | 'L'<<8 | 'O'<<16 | 'F'<<24
	messageTypeFinal        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'F'<<24
	messageTypeChunk        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'C'<<24
	messageTypeAbort        uint32 = 'M' | 'S'<<8 | 'G'<<16 | 'A'<<24
)
