// Copyright 2020 Converter Systems LLC. All rights reserved.

package ua

import (
	"fmt"
	"strconv"
	"strings"
)

// ExpandedNodeID identifies a remote Node.
type ExpandedNodeID struct {
	ServerIndex  uint32
	NamespaceURI string
	NodeID       NodeID
}

func NewExpandedNodeID(nodeID NodeID) ExpandedNodeID {
	return ExpandedNodeID{0, "", nodeID}
}

// NilExpandedNodeID is the nil value.
var NilExpandedNodeID = ExpandedNodeID{0, "", nil}

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
	if n.ServerIndex > 0 {
		fmt.Fprintf(b, "svr=%d;", n.ServerIndex)
	}
	if len(n.NamespaceURI) > 0 {
		fmt.Fprintf(b, "nsu=%s;", n.NamespaceURI)
	}
	switch n2 := n.NodeID.(type) {
	case NodeIDNumeric:
		b.WriteString(n2.String())
	case NodeIDString:
		b.WriteString(n2.String())
	case NodeIDGUID:
		b.WriteString(n2.String())
	case NodeIDOpaque:
		b.WriteString(n2.String())
	default:
		b.WriteString("i=0")
	}
	return b.String()
}

// ToNodeID converts ExpandedNodeID to NodeID by looking up the NamespaceURI and replacing it with the index.
func ToNodeID(n ExpandedNodeID, namespaceURIs []string) NodeID {
	if n.NamespaceURI == "" {
		return n.NodeID
	}
	ns := uint16(0)
	flag := false
	for i, uri := range namespaceURIs {
		if uri == n.NamespaceURI {
			ns = uint16(i)
			flag = true
			break
		}
	}
	if !flag {
		return nil
	}
	switch n2 := n.NodeID.(type) {
	case NodeIDNumeric:
		return NodeIDNumeric{ns, n2.ID}
	case NodeIDString:
		return NodeIDString{ns, n2.ID}
	case NodeIDGUID:
		return NodeIDGUID{ns, n2.ID}
	case NodeIDOpaque:
		return NodeIDOpaque{ns, n2.ID}
	default:
		return nil
	}
}
