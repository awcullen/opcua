// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"fmt"
	"time"

	uuid "github.com/google/uuid"
)

// DataValue holds the value, quality and timestamp
type DataValue struct {
	value             *Variant
	statusCode        StatusCode
	sourceTimestamp   time.Time
	sourcePicoseconds uint16
	serverTimestamp   time.Time
	serverPicoseconds uint16
}

// NewDataValueVariant returns a new DataValue.
func NewDataValueVariant(value *Variant, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{value, statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueBoolean returns a new DataValue.
func NewDataValueBoolean(value bool, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantBoolean(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueSByte returns a new DataValue.
func NewDataValueSByte(value int8, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantSByte(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueByte returns a new DataValue.
func NewDataValueByte(value byte, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantByte(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt16 returns a new DataValue.
func NewDataValueInt16(value int16, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt16(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt16 returns a new DataValue.
func NewDataValueUInt16(value uint16, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt16(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt32 returns a new DataValue.
func NewDataValueInt32(value int32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt32(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt32 returns a new DataValue.
func NewDataValueUInt32(value uint32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt32(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt64 returns a new DataValue.
func NewDataValueInt64(value int64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt64(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt64 returns a new DataValue.
func NewDataValueUInt64(value uint64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt64(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueFloat returns a new DataValue.
func NewDataValueFloat(value float32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantFloat(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDouble returns a new DataValue.
func NewDataValueDouble(value float64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDouble(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueString returns a new DataValue.
func NewDataValueString(value string, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantString(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDateTime returns a new DataValue.
func NewDataValueDateTime(value time.Time, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDateTime(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueGUID returns a new DataValue.
func NewDataValueGUID(value uuid.UUID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantGUID(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueByteString returns a new DataValue.
func NewDataValueByteString(value ByteString, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantByteString(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueXMLElement returns a new DataValue.
func NewDataValueXMLElement(value XMLElement, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantXMLElement(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueNodeID returns a new DataValue.
func NewDataValueNodeID(value NodeID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantNodeID(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueExpandedNodeID returns a new DataValue.
func NewDataValueExpandedNodeID(value ExpandedNodeID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantExpandedNodeID(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueStatusCode returns a new DataValue.
func NewDataValueStatusCode(value StatusCode, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantStatusCode(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueQualifiedName returns a new DataValue.
func NewDataValueQualifiedName(value QualifiedName, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantQualifiedName(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueLocalizedText returns a new DataValue.
func NewDataValueLocalizedText(value LocalizedText, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantLocalizedText(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueObject returns a new DataValue.
func NewDataValueObject(value interface{}, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantObject(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueBooleanArray returns a new DataValue.
func NewDataValueBooleanArray(value []bool, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantBooleanArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueSByteArray returns a new DataValue.
func NewDataValueSByteArray(value []int8, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantSByteArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueByteArray returns a new DataValue.
func NewDataValueByteArray(value []byte, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantByteArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt16Array returns a new DataValue.
func NewDataValueInt16Array(value []int16, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt16Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt16Array returns a new DataValue.
func NewDataValueUInt16Array(value []uint16, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt16Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt32Array returns a new DataValue.
func NewDataValueInt32Array(value []int32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt32Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt32Array returns a new DataValue.
func NewDataValueUInt32Array(value []uint32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt32Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueInt64Array returns a new DataValue.
func NewDataValueInt64Array(value []int64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantInt64Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueUInt64Array returns a new DataValue.
func NewDataValueUInt64Array(value []uint64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantUInt64Array(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueFloatArray returns a new DataValue.
func NewDataValueFloatArray(value []float32, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantFloatArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDoubleArray returns a new DataValue.
func NewDataValueDoubleArray(value []float64, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDoubleArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueStringArray returns a new DataValue.
func NewDataValueStringArray(value []string, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantStringArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDateTimeArray returns a new DataValue.
func NewDataValueDateTimeArray(value []time.Time, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDateTimeArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueGUIDArray returns a new DataValue.
func NewDataValueGUIDArray(value []uuid.UUID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantGUIDArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueByteStringArray returns a new DataValue.
func NewDataValueByteStringArray(value []ByteString, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantByteStringArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueXMLElementArray returns a new DataValue.
func NewDataValueXMLElementArray(value []XMLElement, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantXMLElementArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueNodeIDArray returns a new DataValue.
func NewDataValueNodeIDArray(value []NodeID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantNodeIDArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueExpandedNodeIDArray returns a new DataValue.
func NewDataValueExpandedNodeIDArray(value []ExpandedNodeID, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantExpandedNodeIDArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueStatusCodeArray returns a new DataValue.
func NewDataValueStatusCodeArray(value []StatusCode, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantStatusCodeArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueQualifiedNameArray returns a new DataValue.
func NewDataValueQualifiedNameArray(value []QualifiedName, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantQualifiedNameArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueLocalizedTextArray returns a new DataValue.
func NewDataValueLocalizedTextArray(value []LocalizedText, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantLocalizedTextArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueObjectArray returns a new DataValue.
func NewDataValueObjectArray(value []interface{}, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantObjectArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDataValueArray returns a new DataValue.
func NewDataValueDataValueArray(value []*DataValue, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDataValueArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueVariantArray returns a new DataValue.
func NewDataValueVariantArray(value []*Variant, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantVariantArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// NewDataValueDiagnosticInfoArray returns a new DataValue.
func NewDataValueDiagnosticInfoArray(value []*DiagnosticInfo, statusCode StatusCode, sourceTimestamp time.Time, sourcePicoseconds uint16, serverTimestamp time.Time, serverPicoseconds uint16) *DataValue {
	return &DataValue{NewVariantDiagnosticInfoArray(value), statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
}

// Value returns the value.
func (value *DataValue) Value() interface{} {
	return value.value.Value()
}

// InnerVariant returns the inner variant
func (value *DataValue) InnerVariant() *Variant {
	return value.value
}

// StatusCode returns the status code
func (value *DataValue) StatusCode() StatusCode {
	return value.statusCode
}

// SourceTimestamp returns the source timestamp.
func (value *DataValue) SourceTimestamp() time.Time {
	return value.sourceTimestamp
}

// SourcePicoseconds returns the source picoseconds.
func (value *DataValue) SourcePicoseconds() uint16 {
	return value.sourcePicoseconds
}

// ServerTimestamp returns the server timestamp.
func (value *DataValue) ServerTimestamp() time.Time {
	return value.serverTimestamp
}

// ServerPicoseconds returns the server picoseconds.
func (value *DataValue) ServerPicoseconds() uint16 {
	return value.serverPicoseconds
}

// String returns the value as a string.
func (value *DataValue) String() string {
	return fmt.Sprintf("{%v, 0x%X, %s, %s}", value.value, uint32(value.statusCode), value.sourceTimestamp, value.serverTimestamp)
}
