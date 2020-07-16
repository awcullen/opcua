// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"fmt"
	"strconv"
	"strings"

	uuid "github.com/google/uuid"
)

// ExpandedNodeID identifies a remote Node.
type ExpandedNodeID struct {
	serverIndex  uint32
	namespaceURI string
	nodeID       NodeID
}

// NewExpandedNodeID casts an ExpandedNodeID from a NodeID.
func NewExpandedNodeID(nodeID NodeID) ExpandedNodeID {
	return ExpandedNodeID{0, "", nodeID}
}

// NewExpandedNodeIDNumeric constructs a new ExpandedNodeID of numeric type.
func NewExpandedNodeIDNumeric(serverIndex uint32, namespaceURI string, identifier uint32) ExpandedNodeID {
	return ExpandedNodeID{serverIndex, namespaceURI, NewNodeIDNumeric(0, identifier)}
}

// NewExpandedNodeIDString constructs a new ExpandedNodeID of string type.
func NewExpandedNodeIDString(serverIndex uint32, namespaceURI string, identifier string) ExpandedNodeID {
	return ExpandedNodeID{serverIndex, namespaceURI, NewNodeIDString(0, identifier)}
}

// NewExpandedNodeIDGUID constructs a new ExpandedNodeID of GUID type.
func NewExpandedNodeIDGUID(serverIndex uint32, namespaceURI string, identifier uuid.UUID) ExpandedNodeID {
	return ExpandedNodeID{serverIndex, namespaceURI, NewNodeIDGUID(0, identifier)}
}

// NewExpandedNodeIDOpaque constructs a new ExpandedNodeID of opaque type.
func NewExpandedNodeIDOpaque(serverIndex uint32, namespaceURI string, identifier ByteString) ExpandedNodeID {
	return ExpandedNodeID{serverIndex, namespaceURI, NewNodeIDOpaque(0, identifier)}
}

// ServerIndex returns the index in the servers table.
func (n ExpandedNodeID) ServerIndex() uint32 {
	return n.serverIndex
}

// NamespaceURI returns the namespace uri.
func (n ExpandedNodeID) NamespaceURI() string {
	return n.namespaceURI
}

// NamespaceIndex returns the namespace index.
func (n ExpandedNodeID) NamespaceIndex() uint16 {
	return n.nodeID.NamespaceIndex()
}

// IDType returns the id type.
func (n ExpandedNodeID) IDType() IDType {
	return n.nodeID.IDType()
}

// Identifier returns the identifier.
func (n ExpandedNodeID) Identifier() interface{} {
	return n.nodeID.Identifier()
}

// NilExpandedNodeID is the nil value.
var NilExpandedNodeID = ExpandedNodeID{0, "", NilNodeID}

// IsNil returns true if the nodeId is nil
func (n ExpandedNodeID) IsNil() bool {
	if n.namespaceURI != "" {
		return false
	}
	return n.nodeID.IsNil()
}

// ParseExpandedNodeID returns a NodeID from a string representation.
//   - ParseExpandedNodeID("i=85") // integer, assumes nsu=http://opcfoundation.org/UA/
//   - ParseExpandedNodeID("nsu=http://www.unifiedautomation.com/DemoServer/;s=Demo.Static.Scalar.Float") // string
//   - ParseExpandedNodeID("nsu=http://www.unifiedautomation.com/DemoServer/;g=5ce9dbce-5d79-434c-9ac3-1cfba9a6e92c") // guid
//   - ParseExpandedNodeID("nsu=http://www.unifiedautomation.com/DemoServer/;b=YWJjZA==") // opaque byte string
func ParseExpandedNodeID(s string) ExpandedNodeID {
	var svr uint64
	var err error
	if strings.HasPrefix(s, "svr=") {
		var pos = strings.Index(s, ";")
		if pos == -1 {
			return NilExpandedNodeID
		}

		svr, err = strconv.ParseUint(s[4:pos], 10, 32)
		if err != nil {
			return NilExpandedNodeID
		}
		s = s[pos+1:]
	}

	var nsu string
	if strings.HasPrefix(s, "nsu=") {
		var pos = strings.Index(s, ";")
		if pos == -1 {
			return NilExpandedNodeID
		}

		nsu = s[4:pos]
		s = s[pos+1:]
	}

	return ExpandedNodeID{uint32(svr), nsu, ParseNodeID(s)}
}

// String returns a string representation of the ExpandedNodeID, e.g. "nsu=http://www.unifiedautomation.com/DemoServer/;s=Demo"
func (n ExpandedNodeID) String() string {
	b := new(strings.Builder)

	if n.serverIndex > 0 {
		fmt.Fprintf(b, "svr=%d;", n.serverIndex)
	}

	if len(n.namespaceURI) > 0 {
		fmt.Fprintf(b, "nsu=%s;", n.namespaceURI)
	}

	b.WriteString(n.nodeID.String())

	return b.String()
}

// ToNodeID converts ExpandedNodeID to NodeID by looking up the NamespaceURI and replacing it with the index.
func (n ExpandedNodeID) ToNodeID(namespaceURIs []string) NodeID {
	if n.namespaceURI == "" {
		return n.nodeID
	}
	ns := uint16(0)
	flag := false
	for i, uri := range namespaceURIs {
		if uri == n.namespaceURI {
			ns = uint16(i)
			flag = true
			break
		}
	}
	if !flag {
		return NilNodeID
	}
	switch n.nodeID.idType {
	case IDTypeNumeric:
		return NewNodeIDNumeric(ns, n.nodeID.nid)
	case IDTypeString:
		return NewNodeIDString(ns, n.nodeID.sid)
	case IDTypeGUID:
		return NewNodeIDGUID(ns, n.nodeID.gid)
	case IDTypeOpaque:
		return NewNodeIDOpaque(ns, n.nodeID.bid)
	default:
		return NilNodeID
	}
}
