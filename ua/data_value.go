// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// DataValue holds the value, quality and timestamp
type DataValue struct {
	Value             Variant
	StatusCode        StatusCode
	SourceTimestamp   time.Time
	SourcePicoseconds uint16
	ServerTimestamp   time.Time
	ServerPicoseconds uint16
}

func NewDataValue(value Variant, status StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) DataValue {
	return DataValue{value, status, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NilDataValue is the nil value.
var NilDataValue = DataValue{}
