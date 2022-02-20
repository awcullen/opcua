// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// Condition structure.
type Condition struct {
	EventID       ByteString
	EventType     NodeID
	SourceNode    NodeID
	SourceName    string
	Time          time.Time
	ReceiveTime   time.Time
	Message       LocalizedText
	Severity      uint16
	ConditionID   NodeID
	ConditionName string
	BranchID      NodeID
	Retain        bool
}

// UnmarshalFields ...
func (evt *Condition) UnmarshalFields(eventFields []Variant) error {
	if len(eventFields) != 12 {
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
	evt.ConditionID, _ = eventFields[8].(NodeID)
	evt.ConditionName, _ = eventFields[9].(string)
	evt.BranchID, _ = eventFields[10].(NodeID)
	evt.Retain, _ = eventFields[11].(bool)
	return nil
}

// GetAttribute ...
func (e *Condition) GetAttribute(clause SimpleAttributeOperand) Variant {
	switch {
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[0]):
		return Variant(e.EventID)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[1]):
		return Variant(e.EventType)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[2]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[3]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[4]):
		return Variant(e.Time)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[5]):
		return Variant(e.ReceiveTime)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[6]):
		return Variant(e.Message)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[7]):
		return Variant(e.Severity)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[8]):
		return Variant(e.ConditionID)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[9]):
		return Variant(e.ConditionName)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[10]):
		return Variant(e.BranchID)
	case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[11]):
		return Variant(e.Retain)
	default:
		return nil
	}
}

// ConditionSelectClauses ...
var ConditionSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("EventType"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceNode"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("SourceName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Time"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("ReceiveTime"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Message"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDBaseEventType, BrowsePath: ParseBrowsePath("Severity"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath(""), AttributeID: AttributeIDNodeID},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("ConditionName"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("BranchId"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDConditionType, BrowsePath: ParseBrowsePath("Retain"), AttributeID: AttributeIDValue},
}
