// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"time"
)

// AlarmCondition structure.
type AlarmCondition struct {
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
	ActiveState    bool
}

// UnmarshalFields ...
func (evt *AlarmCondition) UnmarshalFields(eventFields []Variant) error {
	if len(eventFields) != 15 {
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
	evt.ActiveState, _ = eventFields[14].(bool)
	return nil
}

func (e *AlarmCondition) Where(clause ContentFilter) bool {
	return true
}

func (e *AlarmCondition) Select(clauses []SimpleAttributeOperand) []Variant {
	ret := make([]Variant, len(clauses))
	for i, clause := range clauses {
		switch {
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[0]):
			ret[i] = Variant(e.EventID)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[1]):
			ret[i] = Variant(e.EventType)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[2]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[3]):
			ret[i] = Variant(e.SourceName)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[4]):
			ret[i] = Variant(e.Time)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[5]):
			ret[i] = Variant(e.ReceiveTime)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[6]):
			ret[i] = Variant(e.Message)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[7]):
			ret[i] = Variant(e.Severity)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[8]):
			ret[i] = Variant(e.ConditionID)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[9]):
			ret[i] = Variant(e.ConditionName)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[10]):
			ret[i] = Variant(e.BranchID)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[11]):
			ret[i] = Variant(e.Retain)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[12]):
			ret[i] = Variant(e.AckedState)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[13]):
			ret[i] = Variant(e.ConfirmedState)
		case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[14]):
			ret[i] = Variant(e.ActiveState)
		default:
			ret[i] = nil
		}
	}
	return ret
}

// AlarmConditionSelectClauses ...
var AlarmConditionSelectClauses []SimpleAttributeOperand = []SimpleAttributeOperand{
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
	{TypeDefinitionID: ObjectTypeIDAlarmConditionType, BrowsePath: ParseBrowsePath("ActiveState/Id"), AttributeID: AttributeIDValue},
}
