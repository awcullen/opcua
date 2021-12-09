// Copyright 2020 Converter Systems LLC. All rights reserved.

package ua

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	uuid "github.com/google/uuid"
)

// NodeID identifies a Node.
type NodeID interface {
	nodeID()
}

// NodeIDNumeric is a NodeID of numeric type.
type NodeIDNumeric struct {
	NamespaceIndex uint16
	ID             uint32
}

// NewNodeIDNumeric makes a NodeID of numeric type.
func NewNodeIDNumeric(ns uint16, id uint32) NodeIDNumeric {
	return NodeIDNumeric{ns, id}
}

func (n NodeIDNumeric) nodeID() {}

// String returns a string representation, e.g. "i=85"
func (n NodeIDNumeric) String() string {
	if n.NamespaceIndex == 0 {
		return fmt.Sprintf("i=%d", n.ID)
	}
	return fmt.Sprintf("ns=%d;i=%d", n.NamespaceIndex, n.ID)
}

func (n NodeIDNumeric) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// NodeIDString is a NodeID of string type.
type NodeIDString struct {
	NamespaceIndex uint16
	ID             string
}

// NewNodeIDString makes a NodeID of string type.
func NewNodeIDString(ns uint16, id string) NodeIDString {
	return NodeIDString{ns, id}
}

func (n NodeIDString) nodeID() {}

// String returns a string representation, e.g. "ns=2;s=Demo.Static.Scalar.Float"
func (n NodeIDString) String() string {
	if n.NamespaceIndex == 0 {
		return fmt.Sprintf("s=%s", n.ID)
	}
	return fmt.Sprintf("ns=%d;s=%s", n.NamespaceIndex, n.ID)
}

func (n NodeIDString) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// NodeIDGUID is a NodeID of GUID type.
type NodeIDGUID struct {
	NamespaceIndex uint16
	ID             uuid.UUID
}

// NewNodeIDGUID makes a NodeID of GUID type.
func NewNodeIDGUID(ns uint16, id uuid.UUID) NodeIDGUID {
	return NodeIDGUID{ns, id}
}

func (n NodeIDGUID) nodeID() {}

// String returns a string representation, e.g. "ns=2;g=5ce9dbce-5d79-434c-9ac3-1cfba9a6e92c"
func (n NodeIDGUID) String() string {
	if n.NamespaceIndex == 0 {
		return fmt.Sprintf("g=%s", n.ID)
	}
	return fmt.Sprintf("ns=%d;g=%s", n.NamespaceIndex, n.ID)
}

func (n NodeIDGUID) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// NodeIDOpaque is a new NodeID of opaque type.
type NodeIDOpaque struct {
	NamespaceIndex uint16
	ID             ByteString
}

// NewNodeIDOpaque makes a NodeID of opaque type.
func NewNodeIDOpaque(ns uint16, id ByteString) NodeIDOpaque {
	return NodeIDOpaque{ns, id}
}

func (n NodeIDOpaque) nodeID() {}

// String returns a string representation, e.g. "ns=2;b=YWJjZA=="
func (n NodeIDOpaque) String() string {
	if n.NamespaceIndex == 0 {
		return fmt.Sprintf("b=%s", base64.StdEncoding.EncodeToString([]byte(n.ID)))
	}
	return fmt.Sprintf("ns=%d;b=%s", n.NamespaceIndex, base64.StdEncoding.EncodeToString([]byte(n.ID)))
}

func (n NodeIDOpaque) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
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
			return nil
		}
		ns, err = strconv.ParseUint(s[3:pos], 10, 16)
		if err != nil {
			return nil
		}
		s = s[pos+1:]
	}
	switch {
	case strings.HasPrefix(s, "i="):
		var id, err = strconv.ParseUint(s[2:], 10, 32)
		if err != nil {
			return nil
		}
		if id == 0 && ns == 0 {
			return nil
		}
		return NodeIDNumeric{uint16(ns), uint32(id)}
	case strings.HasPrefix(s, "s="):
		return NodeIDString{uint16(ns), s[2:]}
	case strings.HasPrefix(s, "g="):
		var id, err = uuid.Parse(s[2:])
		if err != nil {
			return nil
		}
		return NodeIDGUID{uint16(ns), id}
	case strings.HasPrefix(s, "b="):
		var id, err = base64.StdEncoding.DecodeString(s[2:])
		if err != nil {
			return nil
		}
		return NodeIDOpaque{uint16(ns), ByteString(id)}
	}
	return nil
}

// ToExpandedNodeID converts the NodeID to an ExpandedNodeID.
// Note: When creating a reference, and the target NodeID is a local node,
// use: NewExpandedNodeID(nodeId)
func ToExpandedNodeID(n NodeID, namespaceURIs []string) ExpandedNodeID {
	switch n2 := n.(type) {
	case NodeIDNumeric:
		if n2.NamespaceIndex > 0 && n2.NamespaceIndex < uint16(len(namespaceURIs)) {
			return ExpandedNodeID{0, namespaceURIs[n2.NamespaceIndex], n}
		}
		return ExpandedNodeID{NodeID: n}
	case NodeIDString:
		if n2.NamespaceIndex > 0 && n2.NamespaceIndex < uint16(len(namespaceURIs)) {
			return ExpandedNodeID{0, namespaceURIs[n2.NamespaceIndex], n}
		}
		return ExpandedNodeID{NodeID: n}
	case NodeIDGUID:
		if n2.NamespaceIndex > 0 && n2.NamespaceIndex < uint16(len(namespaceURIs)) {
			return ExpandedNodeID{0, namespaceURIs[n2.NamespaceIndex], n}
		}
		return ExpandedNodeID{NodeID: n}
	case NodeIDOpaque:
		if n2.NamespaceIndex > 0 && n2.NamespaceIndex < uint16(len(namespaceURIs)) {
			return ExpandedNodeID{0, namespaceURIs[n2.NamespaceIndex], n}
		}
		return ExpandedNodeID{NodeID: n}
	default:
		return NilExpandedNodeID
	}
}
