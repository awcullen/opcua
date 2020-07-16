// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"reflect"
	"strconv"
	"time"
)

// BaseEvent structure.
type BaseEvent struct {
	EventID    ByteString    `typeDefinitionId:"i=2041" browsePath:"EventId"`
	EventType  NodeID        `typeDefinitionId:"i=2041" browsePath:"EventType"`
	SourceName string        `typeDefinitionId:"i=2041" browsePath:"SourceName"`
	Time       time.Time     `typeDefinitionId:"i=2041" browsePath:"Time"`
	Message    LocalizedText `typeDefinitionId:"i=2041" browsePath:"Message"`
	Severity   uint16        `typeDefinitionId:"i=2041" browsePath:"Severity"`
}

// Condition structure.
type Condition struct {
	EventID       ByteString    `typeDefinitionId:"i=2041" browsePath:"EventId"`
	EventType     NodeID        `typeDefinitionId:"i=2041" browsePath:"EventType"`
	SourceName    string        `typeDefinitionId:"i=2041" browsePath:"SourceName"`
	Time          time.Time     `typeDefinitionId:"i=2041" browsePath:"Time"`
	Message       LocalizedText `typeDefinitionId:"i=2041" browsePath:"Message"`
	Severity      uint16        `typeDefinitionId:"i=2041" browsePath:"Severity"`
	ConditionID   NodeID        `typeDefinitionId:"i=2782" attributeId:"1"`
	ConditionName string        `typeDefinitionId:"i=2782" browsePath:"ConditionName"`
	BranchID      NodeID        `typeDefinitionId:"i=2782" browsePath:"BranchId"`
	Retain        bool          `typeDefinitionId:"i=2782" browsePath:"Retain"`
}

// AcknowledgeableCondition structure.
type AcknowledgeableCondition struct {
	EventID        ByteString    `typeDefinitionId:"i=2041" browsePath:"EventId"`
	EventType      NodeID        `typeDefinitionId:"i=2041" browsePath:"EventType"`
	SourceName     string        `typeDefinitionId:"i=2041" browsePath:"SourceName"`
	Time           time.Time     `typeDefinitionId:"i=2041" browsePath:"Time"`
	Message        LocalizedText `typeDefinitionId:"i=2041" browsePath:"Message"`
	Severity       uint16        `typeDefinitionId:"i=2041" browsePath:"Severity"`
	ConditionID    NodeID        `typeDefinitionId:"i=2782" attributeId:"1"`
	ConditionName  string        `typeDefinitionId:"i=2782" browsePath:"ConditionName"`
	BranchID       NodeID        `typeDefinitionId:"i=2782" browsePath:"BranchId"`
	Retain         bool          `typeDefinitionId:"i=2782" browsePath:"Retain"`
	AckedState     bool          `typeDefinitionId:"i=2881" browsePath:"AckedState/Id"`
	ConfirmedState bool          `typeDefinitionId:"i=2881" browsePath:"ConfirmedState/Id"`
}

// AlarmCondition structure.
type AlarmCondition struct {
	EventID        ByteString    `typeDefinitionId:"i=2041" browsePath:"EventId"`
	EventType      NodeID        `typeDefinitionId:"i=2041" browsePath:"EventType"`
	SourceName     string        `typeDefinitionId:"i=2041" browsePath:"SourceName"`
	Time           time.Time     `typeDefinitionId:"i=2041" browsePath:"Time"`
	Message        LocalizedText `typeDefinitionId:"i=2041" browsePath:"Message"`
	Severity       uint16        `typeDefinitionId:"i=2041" browsePath:"Severity"`
	ConditionID    NodeID        `typeDefinitionId:"i=2782" attributeId:"1"`
	ConditionName  string        `typeDefinitionId:"i=2782" browsePath:"ConditionName"`
	BranchID       NodeID        `typeDefinitionId:"i=2782" browsePath:"BranchId"`
	Retain         bool          `typeDefinitionId:"i=2782" browsePath:"Retain"`
	AckedState     bool          `typeDefinitionId:"i=2881" browsePath:"AckedState/Id"`
	ConfirmedState bool          `typeDefinitionId:"i=2881" browsePath:"ConfirmedState/Id"`
	ActiveState    bool          `typeDefinitionId:"i=2915" browsePath:"ActiveState/Id"`
}

// DeserializeEvent sets the value's fields with the values of the Variants.
func DeserializeEvent(value interface{}, eventFields []*Variant) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return BadInvalidArgument
	}
	rv = rv.Elem()
	numFields := rv.Type().NumField()
	if numFields != len(eventFields) {
		return BadInvalidArgument
	}
	for i := 0; i < numFields; i++ {
		ef := eventFields[i]
		if !ef.IsNil() {
			rv.Field(i).Set(reflect.ValueOf(ef.Value()))
		}
	}
	return nil
}

// GetSelectClauses returns the SimpleAttributeOperands defined by the fields of an event type.
func GetSelectClauses(typ reflect.Type) []*SimpleAttributeOperand {
	numFields := typ.NumField()
	clauses := make([]*SimpleAttributeOperand, numFields)
	parseAttributeID := func(s string) uint32 {
		if i, err := strconv.Atoi(s); err == nil {
			return uint32(i)
		}
		return AttributeIDValue
	}
	for i := 0; i < numFields; i++ {
		tag := typ.Field(i).Tag
		clauses[i] = &SimpleAttributeOperand{
			TypeDefinitionID: ParseNodeID(tag.Get("typeDefinitionID")),
			BrowsePath:       ParseBrowsePath(tag.Get("browsePath")),
			AttributeID:      parseAttributeID(tag.Get("attributeID")),
			IndexRange:       tag.Get("indexRange"),
		}
	}
	return clauses
}
