// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"fmt"
	"reflect"
	"sync"
)

var (
	binaryEncodingTypes sync.Map // map[ExpandedNodeID]reflect.Type
	binaryEncodingIDs   sync.Map // map[reflect.Type]ExpandedNodeID
)

// RegisterBinaryEncodingID registers the type and id with the BinaryEncoder.
func RegisterBinaryEncodingID(typ reflect.Type, id ExpandedNodeID) {

	if t, dup := binaryEncodingTypes.LoadOrStore(id, typ); dup && t != typ {
		panic(fmt.Sprintf("RegisterBinaryEncodingID: registering duplicate types for %q: %s != %s", id, t, typ))
	}

	if n, dup := binaryEncodingIDs.LoadOrStore(typ, id); dup && n != id {
		binaryEncodingTypes.Delete(id)
		panic(fmt.Sprintf("RegisterBinaryEncodingID: registering duplicate ids for %s: %q != %q", typ, n, id))
	}

}

// FindBinaryEncodingIDForType finds the BinaryEncodingID given the type.
func FindBinaryEncodingIDForType(typ reflect.Type) (ExpandedNodeID, bool) {
	if val, ok := binaryEncodingIDs.Load(typ); ok {
		if id, ok := val.(ExpandedNodeID); ok {
			return id, ok
		}
	}
	return NilExpandedNodeID, false
}

// FindTypeForBinaryEncodingID finds the Type given the BinaryEncodingID.
func FindTypeForBinaryEncodingID(id ExpandedNodeID) (reflect.Type, bool) {
	if val, ok := binaryEncodingTypes.Load(id); ok {
		if typ, ok := val.(reflect.Type); ok {
			return typ, ok
		}
	}
	return nil, false
}
