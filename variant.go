// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"time"

	uuid "github.com/google/uuid"
)

var (
	validXML = regexp.MustCompile(`[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000-x10FFFF]+`)
)

// XMLElement is stored as string
type XMLElement string

// String returns element as a string.
func (e XMLElement) String() string {
	return validXML.ReplaceAllString(string(e), "")
}

// ByteString is stored as a string.
type ByteString string

// NilByteString is the nil value.
var NilByteString = ByteString("")

// String returns ByteString as a base64-encoded string.
func (b ByteString) String() string {
	return base64.StdEncoding.EncodeToString([]byte(b))
}

// MarshalJSON returns ByteString as a base64-encoded string.
func (b ByteString) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(b))
}

// VariantType is the kind of value stored in the Variant.
type VariantType int32

// VariantTypes
const (
	VariantTypeNull VariantType = iota
	VariantTypeBoolean
	VariantTypeSByte
	VariantTypeByte
	VariantTypeInt16
	VariantTypeUInt16
	VariantTypeInt32
	VariantTypeUInt32
	VariantTypeInt64
	VariantTypeUInt64
	VariantTypeFloat
	VariantTypeDouble
	VariantTypeString
	VariantTypeDateTime
	VariantTypeGUID
	VariantTypeByteString
	VariantTypeXMLElement
	VariantTypeNodeID
	VariantTypeExpandedNodeID
	VariantTypeStatusCode
	VariantTypeQualifiedName
	VariantTypeLocalizedText
	VariantTypeExtensionObject
	VariantTypeDataValue
	VariantTypeVariant
	VariantTypeDiagnosticInfo
)

// Variant wraps a value.
type Variant struct {
	value           interface{}
	variantType     VariantType
	arrayDimensions []int32
}

// NewVariantBoolean returns a new Variant.
func NewVariantBoolean(value bool) *Variant {
	return &Variant{value, VariantTypeBoolean, []int32{}}
}

// NewVariantSByte returns a new Variant.
func NewVariantSByte(value int8) *Variant {
	return &Variant{value, VariantTypeSByte, []int32{}}
}

// NewVariantByte returns a new Variant.
func NewVariantByte(value byte) *Variant {
	return &Variant{value, VariantTypeByte, []int32{}}
}

// NewVariantInt16 returns a new Variant.
func NewVariantInt16(value int16) *Variant {
	return &Variant{value, VariantTypeInt16, []int32{}}
}

// NewVariantUInt16 returns a new Variant.
func NewVariantUInt16(value uint16) *Variant {
	return &Variant{value, VariantTypeUInt16, []int32{}}
}

// NewVariantInt32 returns a new Variant.
func NewVariantInt32(value int32) *Variant {
	return &Variant{value, VariantTypeInt32, []int32{}}
}

// NewVariantUInt32 returns a new Variant.
func NewVariantUInt32(value uint32) *Variant {
	return &Variant{value, VariantTypeUInt32, []int32{}}
}

// NewVariantInt64 returns a new Variant.
func NewVariantInt64(value int64) *Variant {
	return &Variant{value, VariantTypeInt64, []int32{}}
}

// NewVariantUInt64 returns a new Variant.
func NewVariantUInt64(value uint64) *Variant {
	return &Variant{value, VariantTypeUInt64, []int32{}}
}

// NewVariantFloat returns a new Variant.
func NewVariantFloat(value float32) *Variant {
	return &Variant{value, VariantTypeFloat, []int32{}}
}

// NewVariantDouble returns a new Variant.
func NewVariantDouble(value float64) *Variant {
	return &Variant{value, VariantTypeDouble, []int32{}}
}

// NewVariantString returns a new Variant.
func NewVariantString(value string) *Variant {
	return &Variant{value, VariantTypeString, []int32{}}
}

// NewVariantDateTime returns a new Variant.
func NewVariantDateTime(value time.Time) *Variant {
	return &Variant{value, VariantTypeDateTime, []int32{}}
}

// NewVariantGUID returns a new Variant.
func NewVariantGUID(value uuid.UUID) *Variant {
	return &Variant{value, VariantTypeGUID, []int32{}}
}

// NewVariantByteString returns a new Variant.
func NewVariantByteString(value ByteString) *Variant {
	return &Variant{value, VariantTypeByteString, []int32{}}
}

// NewVariantXMLElement returns a new Variant.
func NewVariantXMLElement(value XMLElement) *Variant {
	return &Variant{value, VariantTypeXMLElement, []int32{}}
}

// NewVariantNodeID returns a new Variant.
func NewVariantNodeID(value NodeID) *Variant {
	return &Variant{value, VariantTypeNodeID, []int32{}}
}

// NewVariantExpandedNodeID returns a new Variant.
func NewVariantExpandedNodeID(value ExpandedNodeID) *Variant {
	return &Variant{value, VariantTypeExpandedNodeID, []int32{}}
}

// NewVariantStatusCode returns a new Variant.
func NewVariantStatusCode(value StatusCode) *Variant {
	return &Variant{value, VariantTypeStatusCode, []int32{}}
}

// NewVariantQualifiedName returns a new Variant.
func NewVariantQualifiedName(value QualifiedName) *Variant {
	return &Variant{value, VariantTypeQualifiedName, []int32{}}
}

// NewVariantLocalizedText returns a new Variant.
func NewVariantLocalizedText(value LocalizedText) *Variant {
	return &Variant{value, VariantTypeLocalizedText, []int32{}}
}

// NewVariantObject returns a new Variant.
func NewVariantObject(value interface{}) *Variant {
	return &Variant{value, VariantTypeExtensionObject, []int32{}}
}

// NewVariantBooleanArray returns a new Variant.
func NewVariantBooleanArray(value []bool) *Variant {
	return &Variant{value, VariantTypeBoolean, []int32{int32(len(value))}}
}

// NewVariantSByteArray returns a new Variant.
func NewVariantSByteArray(value []int8) *Variant {
	return &Variant{value, VariantTypeSByte, []int32{int32(len(value))}}
}

// NewVariantByteArray returns a new Variant.
func NewVariantByteArray(value []byte) *Variant {
	return &Variant{value, VariantTypeByte, []int32{int32(len(value))}}
}

// NewVariantInt16Array returns a new Variant.
func NewVariantInt16Array(value []int16) *Variant {
	return &Variant{value, VariantTypeInt16, []int32{int32(len(value))}}
}

// NewVariantUInt16Array returns a new Variant.
func NewVariantUInt16Array(value []uint16) *Variant {
	return &Variant{value, VariantTypeUInt16, []int32{int32(len(value))}}
}

// NewVariantInt32Array returns a new Variant.
func NewVariantInt32Array(value []int32) *Variant {
	return &Variant{value, VariantTypeInt32, []int32{int32(len(value))}}
}

// NewVariantUInt32Array returns a new Variant.
func NewVariantUInt32Array(value []uint32) *Variant {
	return &Variant{value, VariantTypeUInt32, []int32{int32(len(value))}}
}

// NewVariantInt64Array returns a new Variant.
func NewVariantInt64Array(value []int64) *Variant {
	return &Variant{value, VariantTypeInt64, []int32{int32(len(value))}}
}

// NewVariantUInt64Array returns a new Variant.
func NewVariantUInt64Array(value []uint64) *Variant {
	return &Variant{value, VariantTypeUInt64, []int32{int32(len(value))}}
}

// NewVariantFloatArray returns a new Variant.
func NewVariantFloatArray(value []float32) *Variant {
	return &Variant{value, VariantTypeFloat, []int32{int32(len(value))}}
}

// NewVariantDoubleArray returns a new Variant.
func NewVariantDoubleArray(value []float64) *Variant {
	return &Variant{value, VariantTypeDouble, []int32{int32(len(value))}}
}

// NewVariantStringArray returns a new Variant.
func NewVariantStringArray(value []string) *Variant {
	return &Variant{value, VariantTypeString, []int32{int32(len(value))}}
}

// NewVariantDateTimeArray returns a new Variant.
func NewVariantDateTimeArray(value []time.Time) *Variant {
	return &Variant{value, VariantTypeDateTime, []int32{int32(len(value))}}
}

// NewVariantGUIDArray returns a new Variant.
func NewVariantGUIDArray(value []uuid.UUID) *Variant {
	return &Variant{value, VariantTypeGUID, []int32{int32(len(value))}}
}

// NewVariantByteStringArray returns a new Variant.
func NewVariantByteStringArray(value []ByteString) *Variant {
	return &Variant{value, VariantTypeByteString, []int32{int32(len(value))}}
}

// NewVariantXMLElementArray returns a new Variant.
func NewVariantXMLElementArray(value []XMLElement) *Variant {
	return &Variant{value, VariantTypeXMLElement, []int32{int32(len(value))}}
}

// NewVariantNodeIDArray returns a new Variant.
func NewVariantNodeIDArray(value []NodeID) *Variant {
	return &Variant{value, VariantTypeNodeID, []int32{int32(len(value))}}
}

// NewVariantExpandedNodeIDArray returns a new Variant.
func NewVariantExpandedNodeIDArray(value []ExpandedNodeID) *Variant {
	return &Variant{value, VariantTypeExpandedNodeID, []int32{int32(len(value))}}
}

// NewVariantStatusCodeArray returns a new Variant.
func NewVariantStatusCodeArray(value []StatusCode) *Variant {
	return &Variant{value, VariantTypeStatusCode, []int32{int32(len(value))}}
}

// NewVariantQualifiedNameArray returns a new Variant.
func NewVariantQualifiedNameArray(value []QualifiedName) *Variant {
	return &Variant{value, VariantTypeQualifiedName, []int32{int32(len(value))}}
}

// NewVariantLocalizedTextArray returns a new Variant.
func NewVariantLocalizedTextArray(value []LocalizedText) *Variant {
	return &Variant{value, VariantTypeLocalizedText, []int32{int32(len(value))}}
}

// NewVariantObjectArray returns a new Variant.
func NewVariantObjectArray(value []interface{}) *Variant {
	return &Variant{value, VariantTypeExtensionObject, []int32{int32(len(value))}}
}

// NewVariantDataValueArray returns a new Variant.
func NewVariantDataValueArray(value []*DataValue) *Variant {
	return &Variant{value, VariantTypeDataValue, []int32{int32(len(value))}}
}

// NewVariantVariantArray returns a new Variant.
func NewVariantVariantArray(value []*Variant) *Variant {
	return &Variant{value, VariantTypeVariant, []int32{int32(len(value))}}
}

// NewVariantDiagnosticInfoArray returns a new Variant.
func NewVariantDiagnosticInfoArray(value []*DiagnosticInfo) *Variant {
	return &Variant{value, VariantTypeDiagnosticInfo, []int32{int32(len(value))}}
}

// Value returns the value.
func (v *Variant) Value() interface{} {
	return v.value
}

// Type returns the VariantType enumeration.
func (v *Variant) Type() VariantType {
	return v.variantType
}

// ArrayDimensions returns the array dimensions.
func (v *Variant) ArrayDimensions() []int32 {
	return v.arrayDimensions
}

// NilVariant is the nil value.
var NilVariant = Variant{}

// IsNil checks if Variant is nil
func (v *Variant) IsNil() bool {
	return v == nil || v.variantType == VariantTypeNull
}

// Equal checks if the values are equal
func (v *Variant) Equal(b *Variant) bool {
	return v.variantType == b.variantType && reflect.DeepEqual(v.value, b.value)
}
