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

// GetAttribute ...
func (e *AlarmCondition) GetAttribute(clause SimpleAttributeOperand) Variant {
	switch {
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[0]):
		return Variant(e.EventID)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[1]):
		return Variant(e.EventType)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[2]):
		return Variant(e.SourceNode)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[3]):
		return Variant(e.SourceName)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[4]):
		return Variant(e.Time)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[5]):
		return Variant(e.ReceiveTime)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[6]):
		return Variant(e.Message)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[7]):
		return Variant(e.Severity)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[8]):
		return Variant(e.ConditionID)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[9]):
		return Variant(e.ConditionName)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[10]):
		return Variant(e.BranchID)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[11]):
		return Variant(e.Retain)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[12]):
		return Variant(e.AckedState)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[13]):
		return Variant(e.ConfirmedState)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauses[14]):
		return Variant(e.ActiveState)
	case EqualSimpleAttributeOperand(clause, AlarmConditionSelectClauseActiveStateEffectiveDisplayName):
		if e.ActiveState {
			return Variant(LocalizedText{Locale: "en", Text: "Active"})
		} else {
			return Variant(LocalizedText{Locale: "en", Text: "Inactive"})
		}
	default:
		return nil
	}
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

var AlarmConditionSelectClauseActiveStateEffectiveDisplayName SimpleAttributeOperand = SimpleAttributeOperand{TypeDefinitionID: ObjectTypeIDAlarmConditionType, BrowsePath: ParseBrowsePath("ActiveState/EffectiveDisplayName"), AttributeID: AttributeIDValue}
