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

func (e *AcknowledgeableCondition) Where(clause ContentFilter) bool {
	return true
}

func (e *AcknowledgeableCondition) Select(clauses []SimpleAttributeOperand) []Variant {
	ret := make([]Variant, len(clauses))
	for i, clause := range clauses {
		switch {
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[0]):
			ret[i] = Variant(e.EventID)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[1]):
			ret[i] = Variant(e.EventType)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[2]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[3]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[4]):
			ret[i] = Variant(e.Time)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[5]):
			ret[i] = Variant(e.ReceiveTime)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[6]):
			ret[i] = Variant(e.Message)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[7]):
			ret[i] = Variant(e.Severity)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[8]):
			ret[i] = Variant(e.ConditionID)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[9]):
			ret[i] = Variant(e.ConditionName)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[10]):
			ret[i] = Variant(e.BranchID)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[11]):
			ret[i] = Variant(e.Retain)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[12]):
			ret[i] = Variant(e.AckedState)
		case EqualSimpleAttributeOperand(clause, AcknowledgeableConditionSelectClauses[13]):
			ret[i] = Variant(e.ConfirmedState)
		default:
			ret[i] = nil
		}
	}
	return ret
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
