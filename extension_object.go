// Copyright 2021 Converter Systems LLC. All rights reserved.

package opcua

// ExtensionObject stores a struct.
// Register the struct type and id with the BinaryEncoder using
//   func RegisterBinaryEncodingID(typ reflect.Type, id ExpandedNodeID)
type ExtensionObject interface{}
