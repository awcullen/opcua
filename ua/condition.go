// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// Condition structure.
type Condition struct {
	EventID       ByteString
	EventType     NodeID
	SourceName    string
	Time          time.Time
	Message       LocalizedText
	Severity      uint16
	ConditionID   NodeID
	ConditionName string
	BranchID      NodeID
	Retain        bool
}

// NewCondition ...
func NewCondition(eventFields []Variant) *Condition {
	ret := &Condition{}
	if len(eventFields) < 10 {
		return ret
	}
	if v, ok := eventFields[0].(ByteString); ok {
		ret.EventID = v
	}
	if v, ok := eventFields[1].(NodeID); ok {
		ret.EventType = v
	}
	if v, ok := eventFields[2].(string); ok {
		ret.SourceName = v
	}
	if v, ok := eventFields[3].(time.Time); ok {
		ret.Time = v
	}
	if v, ok := eventFields[4].(LocalizedText); ok {
		ret.Message = v
	}
	if v, ok := eventFields[5].(uint16); ok {
		ret.Severity = v
	}
	if v, ok := eventFields[6].(NodeID); ok {
		ret.ConditionID = v
	}
	if v, ok := eventFields[7].(string); ok {
		ret.ConditionName = v
	}
	if v, ok := eventFields[8].(NodeID); ok {
		ret.BranchID = v
	}
	if v, ok := eventFields[9].(bool); ok {
		ret.Retain = v
	}
	return ret
}

// ConditionSelectClauses ...
var ConditionSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventType"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Time"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Message"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Severity"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath(""), AttributeID: AttributeIDNodeID},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("ConditionName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("BranchId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("Retain"), AttributeID: AttributeIDValue},
}
