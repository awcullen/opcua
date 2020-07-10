// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

// ExtensionObjectEncoding indicates the kind of data in the body.
type ExtensionObjectEncoding byte

// ExtensionObjectEncoding indicates the kind of data in the body.
const (
	ExtensionObjectEncodingNone       ExtensionObjectEncoding = 0
	ExtensionObjectEncodingByteString ExtensionObjectEncoding = 1
	ExtensionObjectEncodingXMLElement ExtensionObjectEncoding = 2
)

// ExtensionObject wraps structures and blobs so they can be handled by the encoder.
type ExtensionObject struct {
	body     interface{}
	typeID   ExpandedNodeID
	bodyType ExtensionObjectEncoding
}

// NewExtensionObject constructs an ExtensionObject by specifying the body, BinaryEncodingId, and ExtensionObjectEncoding.
func NewExtensionObject(body interface{}, typeID ExpandedNodeID, bodyType ExtensionObjectEncoding) *ExtensionObject {
	return &ExtensionObject{body, typeID, bodyType}
}

// NewExtensionObjectByteString constructs an ExtensionObject by specifying a slice of bytes and BinaryEncodingId.
func NewExtensionObjectByteString(body ByteString, typeID ExpandedNodeID) *ExtensionObject {
	return &ExtensionObject{body, typeID, ExtensionObjectEncodingByteString}
}

// NewExtensionObjectXMLElement constructs an ExtensionObject by specifying an XmlElement and BinaryEncodingId.
func NewExtensionObjectXMLElement(body XMLElement, typeID ExpandedNodeID) *ExtensionObject {
	return &ExtensionObject{body, typeID, ExtensionObjectEncodingXMLElement}
}

// Body returns the value.
func (a *ExtensionObject) Body() interface{} {
	return a.body
}

// TypeID returns the BinaryEncodingId.
func (a *ExtensionObject) TypeID() ExpandedNodeID {
	return a.typeID
}

// Encoding returns the ExtensionObjectEncoding enumuration.
func (a *ExtensionObject) Encoding() ExtensionObjectEncoding {
	return a.bodyType
}

// NilExtensionObject is the nil value
var NilExtensionObject = ExtensionObject{nil, NilExpandedNodeID, ExtensionObjectEncodingNone}
