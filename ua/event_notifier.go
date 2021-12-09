// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// EventNotifier are flags that can be set for the EventNotifier attribute.
const (
	EventNotifierNone              byte = 0x0
	EventNotifierSubscribeToEvents byte = 0x1
	EventNotifierHistoryRead       byte = 0x4
	EventNotifierHistoryWrite      byte = 0x8
)
