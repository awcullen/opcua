// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// ValueRank identifies the rank of value that may be stored in the Value attribute.
const (
	ValueRankOneDimension         = int32(1)
	ValueRankOneOrMoreDimensions  = int32(0)
	ValueRankScalar               = int32(-1)
	ValueRankAny                  = int32(-2)
	ValueRankScalarOrOneDimension = int32(-3)
)
