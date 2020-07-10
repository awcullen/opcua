// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	uuid "github.com/google/uuid"
)

// NodeID identifies a Node.
type NodeID struct {
	namespaceIndex uint16
	idType         IDType
	nid            uint32
	sid            string
	gid            uuid.UUID
	bid            ByteString
}

// NewNodeIDNumeric constructs a new NodeID of numeric type.
func NewNodeIDNumeric(namespaceIndex uint16, identifier uint32) NodeID {
	return NodeID{namespaceIndex, IDTypeNumeric, identifier, "", uuid.Nil, ""}
}

// NewNodeIDString constructs a new NodeID of string type.
func NewNodeIDString(namespaceIndex uint16, identifier string) NodeID {
	return NodeID{namespaceIndex, IDTypeString, 0, identifier, uuid.Nil, ""}
}

// NewNodeIDGUID constructs a new NodeID of GUID type.
func NewNodeIDGUID(namespaceIndex uint16, identifier uuid.UUID) NodeID {
	return NodeID{namespaceIndex, IDTypeGUID, 0, "", identifier, ""}
}

// NewNodeIDOpaque constructs a new NodeID of opaque type.
func NewNodeIDOpaque(namespaceIndex uint16, identifier ByteString) NodeID {
	return NodeID{namespaceIndex, IDTypeOpaque, 0, "", uuid.Nil, identifier}
}

// NamespaceIndex returns the namespace index.
func (n NodeID) NamespaceIndex() uint16 {
	return n.namespaceIndex
}

// IDType returns the identifier type.
func (n NodeID) IDType() IDType {
	return n.idType
}

// Identifier returns the identifier.
func (n NodeID) Identifier() interface{} {
	switch n.idType {
	case IDTypeNumeric:
		return n.nid
	case IDTypeString:
		return n.sid
	case IDTypeGUID:
		return n.gid
	case IDTypeOpaque:
		return n.bid
	}
	return nil
}

// NilNodeID is the nil value.
var NilNodeID = NodeID{0, 0, 0, "", uuid.Nil, ""}

// IsNil returns true if the nodeId is nil
func (n NodeID) IsNil() bool {
	if n.namespaceIndex > 0 {
		return false
	}
	switch n.idType {
	case IDTypeNumeric:
		return n.nid == 0
	case IDTypeString:
		return len(n.sid) == 0
	case IDTypeGUID:
		return n.gid == uuid.Nil
	case IDTypeOpaque:
		return len(n.bid) == 0
	}
	return false
}

// IsValid returns true if the nodeId is valid
func (n NodeID) IsValid() bool {
	switch n.idType {
	case IDTypeNumeric:
		return n.nid != 0
	case IDTypeString:
		return len(n.sid) <= 4096 && len(n.sid) > 0
	case IDTypeGUID:
		return n.gid != uuid.Nil
	case IDTypeOpaque:
		return len(n.bid) <= 4096 && len(n.bid) > 0
	}
	return false
}

// ParseNodeID returns a NodeID from a string representation.
//   - ParseNodeID("i=85") // integer, assumes ns=0
//   - ParseNodeID("ns=2;s=Demo.Static.Scalar.Float") // string
//   - ParseNodeID("ns=2;g=5ce9dbce-5d79-434c-9ac3-1cfba9a6e92c") // guid
//   - ParseNodeID("ns=2;b=YWJjZA==") // opaque byte string
func ParseNodeID(s string) NodeID {
	var ns uint64
	var err error
	if strings.HasPrefix(s, "ns=") {
		var pos = strings.Index(s, ";")
		if pos == -1 {
			return NilNodeID
		}
		ns, err = strconv.ParseUint(s[3:pos], 10, 16)
		if err != nil {
			return NilNodeID
		}
		s = s[pos+1:]
	}
	switch {
	case strings.HasPrefix(s, "i="):
		var id, err = strconv.ParseUint(s[2:], 10, 32)
		if err != nil {
			return NilNodeID
		}
		return NewNodeIDNumeric(uint16(ns), uint32(id))
	case strings.HasPrefix(s, "s="):
		return NewNodeIDString(uint16(ns), s[2:])
	case strings.HasPrefix(s, "g="):
		var id, err = uuid.Parse(s[2:])
		if err != nil {
			return NilNodeID
		}
		return NewNodeIDGUID(uint16(ns), id)
	case strings.HasPrefix(s, "b="):
		var id, err = base64.StdEncoding.DecodeString(s[2:])
		if err != nil {
			return NilNodeID
		}
		return NewNodeIDOpaque(uint16(ns), ByteString(id))
	}
	return NilNodeID
}

// String returns a string representation of the NodeID, e.g. "ns=2;s=Demo"
func (n NodeID) String() string {
	if n.namespaceIndex > 0 {
		switch n.idType {
		case IDTypeNumeric:
			return fmt.Sprintf("ns=%d;i=%d", n.namespaceIndex, n.nid)
		case IDTypeString:
			return fmt.Sprintf("ns=%d;s=%s", n.namespaceIndex, n.sid)
		case IDTypeGUID:
			return fmt.Sprintf("ns=%d;g=%s", n.namespaceIndex, n.gid)
		case IDTypeOpaque:
			return fmt.Sprintf("ns=%d;b=%s", n.namespaceIndex, base64.StdEncoding.EncodeToString([]byte(n.bid)))
		default:
			return ""
		}
	}
	switch n.idType {
	case IDTypeNumeric:
		return fmt.Sprintf("i=%d", n.nid)
	case IDTypeString:
		return fmt.Sprintf("s=%s", n.sid)
	case IDTypeGUID:
		return fmt.Sprintf("g=%s", n.gid)
	case IDTypeOpaque:
		return fmt.Sprintf("b=%s", base64.StdEncoding.EncodeToString([]byte(n.bid)))
	default:
		return ""
	}
}

// ToExpandedNodeID converts the NodeID to an ExpandedNodeID.
// Note: When creating a reference, and the target NodeID is a local node,
// use: NewExpandedNodeID(nodeId)
func (n NodeID) ToExpandedNodeID(namespaceURIs []string) ExpandedNodeID {
	ns := n.namespaceIndex
	nsu := ""
	if namespaceURIs != nil && ns > 0 && ns < uint16(len(namespaceURIs)) {
		nsu = namespaceURIs[ns]
		switch n.idType {
		case IDTypeNumeric:
			return NewExpandedNodeIDNumeric(0, nsu, n.nid)
		case IDTypeString:
			return NewExpandedNodeIDString(0, nsu, n.sid)
		case IDTypeGUID:
			return NewExpandedNodeIDGUID(0, nsu, n.gid)
		case IDTypeOpaque:
			return NewOpaqueExpandedNodeID(0, nsu, n.bid)
		}
	}
	return ExpandedNodeID{nodeID: n}
}
