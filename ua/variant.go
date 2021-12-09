// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// VariantTypes
const (
	VariantTypeNull byte = iota
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

/*
Variant stores a single value or slice of the following types:

   bool, int8, uint8, int16, uint16, int32, uint32
   int64, uint64, float32, float64, string
   time.Time, uuid.UUID, ByteString, XmlElement
   NodeId, ExpandedNodeId, StatusCode, QualifiedName
   LocalizedText, DataValue, Variant

In addition, you may store any type that is registered with the BinaryEncoder.
These types will be encoded as an ExtensionObject by the BinaryEncoder.

*/
type Variant interface{}
