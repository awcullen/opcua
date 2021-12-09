// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// AttributeID selects which attribute of the node to read or write.
const (
	AttributeIDNodeID                  uint32 = 1
	AttributeIDNodeClass               uint32 = 2
	AttributeIDBrowseName              uint32 = 3
	AttributeIDDisplayName             uint32 = 4
	AttributeIDDescription             uint32 = 5
	AttributeIDWriteMask               uint32 = 6
	AttributeIDUserWriteMask           uint32 = 7
	AttributeIDIsAbstract              uint32 = 8
	AttributeIDSymmetric               uint32 = 9
	AttributeIDInverseName             uint32 = 10
	AttributeIDContainsNoLoops         uint32 = 11
	AttributeIDEventNotifier           uint32 = 12
	AttributeIDValue                   uint32 = 13
	AttributeIDDataType                uint32 = 14
	AttributeIDValueRank               uint32 = 15
	AttributeIDArrayDimensions         uint32 = 16
	AttributeIDAccessLevel             uint32 = 17
	AttributeIDUserAccessLevel         uint32 = 18
	AttributeIDMinimumSamplingInterval uint32 = 19
	AttributeIDHistorizing             uint32 = 20
	AttributeIDExecutable              uint32 = 21
	AttributeIDUserExecutable          uint32 = 22
	AttributeIDDataTypeDefinition      uint32 = 23
	AttributeIDRolePermissions         uint32 = 24
	AttributeIDUserRolePermissions     uint32 = 25
	AttributeIDAccessRestrictions      uint32 = 26
	AttributeIDAccessLevelEx           uint32 = 27
)
