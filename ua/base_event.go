// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// BaseEvent structure.
type BaseEvent struct {
	EventID    ByteString
	EventType  NodeID
	SourceName string
	Time       time.Time
	Message    LocalizedText
	Severity   uint16
}

// NewBaseEvent ...
func NewBaseEvent(eventFields []Variant) *BaseEvent {
	ret := &BaseEvent{}
	if len(eventFields) < 6 {
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
	return ret
}

// BaseEventSelectClauses ...
var BaseEventSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventType"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Time"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Message"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Severity"), AttributeID: AttributeIDValue},
}
