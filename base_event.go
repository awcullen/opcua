// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

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
func NewBaseEvent(eventFields []*Variant) *BaseEvent {
	e := &BaseEvent{}
	for i, f := range eventFields {
		if f.IsNil() {
			continue
		}
		switch i {
		case 0:
			e.EventID = f.Value().(ByteString)
		case 1:
			e.EventType = f.Value().(NodeID)
		case 2:
			e.SourceName = f.Value().(string)
		case 3:
			e.Time = f.Value().(time.Time)
		case 4:
			e.Message = f.Value().(LocalizedText)
		case 5:
			e.Severity = f.Value().(uint16)
		}
	}
	return e
}

// BaseEventSelectClauses ...
var BaseEventSelectClauses []*SimpleAttributeOperand = []*SimpleAttributeOperand{
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventType"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Time"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Message"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Severity"), AttributeID: AttributeIDValue},
}
