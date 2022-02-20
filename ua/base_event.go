// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

type Event interface {
	GetAttribute(clause SimpleAttributeOperand) Variant
}

// BaseEvent structure.
type BaseEvent struct {
	EventID     ByteString
	EventType   NodeID
	SourceNode  NodeID
	SourceName  string
	Time        time.Time
	ReceiveTime time.Time
	Message     LocalizedText
	Severity    uint16
}

// UnmarshalFields ...
func (evt *BaseEvent) UnmarshalFields(eventFields []Variant) error {
	if len(eventFields) != 8 {
		return BadUnexpectedError
	}
	evt.EventID, _ = eventFields[0].(ByteString)
	evt.EventType, _ = eventFields[1].(NodeID)
	evt.SourceNode, _ = eventFields[2].(NodeID)
	evt.SourceName, _ = eventFields[3].(string)
	evt.Time, _ = eventFields[4].(time.Time)
	evt.ReceiveTime, _ = eventFields[5].(time.Time)
	evt.Message, _ = eventFields[6].(LocalizedText)
	evt.Severity, _ = eventFields[7].(uint16)
	return nil
}

// GetAttribute ...
func (e *BaseEvent) GetAttribute(clause SimpleAttributeOperand) Variant {
	switch {
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[0]):
		return Variant(e.EventID)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[1]):
		return Variant(e.EventType)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[2]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[3]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[4]):
		return Variant(e.Time)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[5]):
		return Variant(e.ReceiveTime)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[6]):
		return Variant(e.Message)
	case EqualSimpleAttributeOperand(clause, BaseEventSelectClauses[7]):
		return Variant(e.Severity)
	default:
		return nil
	}
}

// BaseEventSelectClauses ...
var BaseEventSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventType"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceNode"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Time"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("ReceiveTime"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Message"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Severity"), AttributeID: AttributeIDValue},
}
