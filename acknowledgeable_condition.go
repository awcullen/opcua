// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"time"
)

// AcknowledgeableCondition structure.
type AcknowledgeableCondition struct {
	EventID        ByteString
	EventType      NodeID
	SourceName     string
	Time           time.Time
	Message        LocalizedText
	Severity       uint16
	ConditionID    NodeID
	ConditionName  string
	BranchID       NodeID
	Retain         bool
	AckedState     bool
	ConfirmedState bool
}

// NewAcknowledgeableCondition ...
func NewAcknowledgeableCondition(eventFields []*Variant) *AcknowledgeableCondition {
	e := &AcknowledgeableCondition{}
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
		case 6:
			e.ConditionID = f.Value().(NodeID)
		case 7:
			e.ConditionName = f.Value().(string)
		case 8:
			e.BranchID = f.Value().(NodeID)
		case 9:
			e.Retain = f.Value().(bool)
		case 10:
			e.AckedState = f.Value().(bool)
		case 11:
			e.ConfirmedState = f.Value().(bool)
		}
	}
	return e
}

// AcknowledgeableConditionSelectClauses ...
var AcknowledgeableConditionSelectClauses []*SimpleAttributeOperand = []*SimpleAttributeOperand{
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
	{TypeDefinitionID: ObjectTypeIDAcknowledgeableConditionType, BrowsePath: ParseBrowsePath("AckedState/Id"), AttributeID: AttributeIDValue},
	{TypeDefinitionID: ObjectTypeIDAcknowledgeableConditionType, BrowsePath: ParseBrowsePath("ConfirmedState/Id"), AttributeID: AttributeIDValue},
}
