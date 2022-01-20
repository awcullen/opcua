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


func (e *Condition) Where(clause ContentFilter) bool {
	return true
}

func (e *Condition) Select(clauses []SimpleAttributeOperand) []Variant {
	ret := make([]Variant, len(clauses))
	for i, clause := range clauses {
		switch {
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[0]):
			ret[i] = Variant(e.EventID)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[1]):
			ret[i] = Variant(e.EventType)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[2]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[3]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[4]):
			ret[i] = Variant(e.Time)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[5]):
			ret[i] = Variant(e.ReceiveTime)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[6]):
			ret[i] = Variant(e.Message)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[7]):
			ret[i] = Variant(e.Severity)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[8]):
			ret[i] = Variant(e.ConditionID)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[9]):
			ret[i] = Variant(e.ConditionName)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[10]):
			ret[i] = Variant(e.BranchID)
		case EqualSimpleAttributeOperand(clause, ConditionSelectClauses[11]):
			ret[i] = Variant(e.Retain)
		default:
			ret[i] = nil
		}
	}
	return ret
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
