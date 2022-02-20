// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// AcknowledgeableCondition structure.
type AcknowledgeableCondition struct {
	EventID        ByteString
	EventType      NodeID
	SourceNode     NodeID
	SourceName     string
	Time           time.Time
	ReceiveTime    time.Time
	Message        LocalizedText
	Severity       uint16
	ConditionID    NodeID
	ConditionName  string
	BranchID       NodeID
	Retain         bool
	AckedState     bool
	ConfirmedState bool
}

// UnmarshalFields ...
func (evt *AcknowledgeableCondition) UnmarshalFields(eventFields []Variant) error {
	if len(eventFields) != 14 {
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
	evt.AckedState, _ = eventFields[12].(bool)
	evt.ConfirmedState, _ = eventFields[13].(bool)
	return nil
}

// GetAttribute ...
func (e *AcknowledgeableCondition) GetAttribute(clause SimpleAttributeOperand) Variant {
	switch {
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[0]):
		return Variant(e.EventID)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[1]):
		return Variant(e.EventType)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[2]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[3]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[4]):
		return Variant(e.Time)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[5]):
		return Variant(e.ReceiveTime)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[6]):
		return Variant(e.Message)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[7]):
		return Variant(e.Severity)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[8]):
		return Variant(e.ConditionID)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[9]):
		return Variant(e.ConditionName)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[10]):
		return Variant(e.BranchID)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[11]):
		return Variant(e.Retain)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[12]):
		return Variant(e.AckedState)
	case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[13]):
		return Variant(e.ConfirmedState)
	default:
		return nil
	}
}

// AcknowledgeableConditionSelectClauses ...
var AcknowledgeableConditionSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
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
	{TypeDefinitionID: ObjectTypeIDAcknowledgeableConditionType, BrowsePath: ParseBrowsePath("AckedState/Id"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDAcknowledgeableConditionType, BrowsePath: ParseBrowsePath("ConfirmedState/Id"), AttributeID: AttributeIDValue},
}
