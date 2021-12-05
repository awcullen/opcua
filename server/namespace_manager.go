// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awcullen/opcua"

	"github.com/gammazero/deque"
	"github.com/google/uuid"
)

var (
	hasChildandSubtypes = []opcua.NodeID{opcua.ReferenceTypeIDHasComponent, opcua.ReferenceTypeIDHasProperty, opcua.ReferenceTypeIDHasSubtype, opcua.ReferenceTypeIDHasOrderedComponent}
)

// NamespaceManager manages the namespaces for a server.
type NamespaceManager struct {
	sync.RWMutex
	server         *Server
	namespaces     []string
	nodes          map[opcua.NodeID]Node
	variantTypeMap map[opcua.NodeID]byte
}

// NewNamespaceManager instantiates a new NamespaceManager.
func NewNamespaceManager(server *Server) *NamespaceManager {
	return &NamespaceManager{
		server:         server,
		namespaces:     []string{"http://opcfoundation.org/UA/", server.LocalDescription().ApplicationURI},
		nodes:          make(map[opcua.NodeID]Node, 4096),
		variantTypeMap: make(map[opcua.NodeID]byte, 32),
	}
}

// Add adds a namespace to the end of the table and returns the index.
// If the namespace already exists then returns the index.
func (m *NamespaceManager) Add(nsu string) uint16 {
	m.Lock()
	defer m.Unlock()
	for i, ns := range m.namespaces {
		if ns == nsu {
			return uint16(i)
		}
	}
	m.namespaces = append(m.namespaces, nsu)
	return uint16(len(m.namespaces) - 1)
}

// Len returns the number of namespace.
func (m *NamespaceManager) Len() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.namespaces)
}

// NamespaceUris returns the namespace table of the server.
func (m *NamespaceManager) NamespaceUris() []string {
	m.RLock()
	defer m.RUnlock()
	return m.namespaces
}

// FindNode returns the node with the given NodeID from the namespace.
func (m *NamespaceManager) FindNode(id opcua.NodeID) (node Node, ok bool) {
	m.RLock()
	defer m.RUnlock()
	node, ok = m.nodes[id]
	return
}

// FindObject returns the node with the given NodeID from the namespace.
func (m *NamespaceManager) FindObject(id opcua.NodeID) (node *ObjectNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*ObjectNode)
	}
	return
}

// FindVariable returns the node with the given NodeID from the namespace.
func (m *NamespaceManager) FindVariable(id opcua.NodeID) (node *VariableNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*VariableNode)
	}
	return
}

// FindProperty returns the property with the given browseName from the namespace.
func (m *NamespaceManager) FindProperty(startNode Node, browseName opcua.QualifiedName) (node *VariableNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	for _, r := range startNode.References() {
		if !r.IsInverse && opcua.ReferenceTypeIDHasProperty == r.ReferenceTypeID {
			id := opcua.ToNodeID(r.TargetID, m.namespaces)
			if node1, ok1 := m.nodes[id]; ok1 {
				if browseName == node1.BrowseName() {
					node, ok = node1.(*VariableNode)
					return
				}
			}
		}
	}
	return
}

// FindComponent returns the component with the given browseName from the namespace.
func (m *NamespaceManager) FindComponent(startNode Node, browseName opcua.QualifiedName) (node Node, ok bool) {
	m.RLock()
	defer m.RUnlock()
	for _, r := range startNode.References() {
		if !r.IsInverse && opcua.ReferenceTypeIDHasComponent == r.ReferenceTypeID {
			id := opcua.ToNodeID(r.TargetID, m.namespaces)
			if node1, ok1 := m.nodes[id]; ok1 {
				if browseName == node1.BrowseName() {
					node, ok = node1, true
					return
				}
			}
		}
	}
	return
}

// FindMethod returns the node with the given NodeID from the namespace.
func (m *NamespaceManager) FindMethod(id opcua.NodeID) (node *MethodNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*MethodNode)
	}
	return
}

// IsSubtype returns whether the subtype is derived from the given supertype in the namespace.
func (m *NamespaceManager) IsSubtype(subtype, supertype opcua.NodeID) bool {
	id := subtype
	i := 0
loop:
	if i > 100 {
		log.Printf("IsSubtype() exceeded limits.\n")
		return false
	}
	i++
	if n, ok := m.FindNode(id); ok {
		for _, r := range n.References() {
			if r.IsInverse && opcua.ReferenceTypeIDHasSubtype == r.ReferenceTypeID {
				id = opcua.ToNodeID(r.TargetID, m.NamespaceUris())
				if supertype == id {
					return true
				}
				goto loop
			}
		}
	}
	return false
}

// FindSuperType returns the immediate supertype for the type.
func (m *NamespaceManager) FindSuperType(typeid opcua.NodeID) opcua.NodeID {
	if n, ok := m.FindNode(typeid); ok {
		for _, r := range n.References() {
			if r.IsInverse && opcua.ReferenceTypeIDHasSubtype == r.ReferenceTypeID {
				return opcua.ToNodeID(r.TargetID, m.NamespaceUris())
			}
		}
	}
	return nil
}

// FindVariantType gets the variant type for the variable
func (m *NamespaceManager) FindVariantType(dataType opcua.NodeID) byte {
	m.RLock()
	vt, ok := m.variantTypeMap[dataType]
	if ok {
		m.RUnlock()
		return vt
	}
	m.RUnlock()
	t := dataType
	for {
		switch t {
		case opcua.DataTypeIDBoolean:
			vt = opcua.VariantTypeBoolean
			goto exit
		case opcua.DataTypeIDSByte:
			vt = opcua.VariantTypeSByte
			goto exit
		case opcua.DataTypeIDByte:
			vt = opcua.VariantTypeByte
			goto exit
		case opcua.DataTypeIDInt16:
			vt = opcua.VariantTypeInt16
			goto exit
		case opcua.DataTypeIDUInt16:
			vt = opcua.VariantTypeUInt16
			goto exit
		case opcua.DataTypeIDInt32:
			vt = opcua.VariantTypeInt32
			goto exit
		case opcua.DataTypeIDUInt32:
			vt = opcua.VariantTypeUInt32
			goto exit
		case opcua.DataTypeIDInt64:
			vt = opcua.VariantTypeInt64
			goto exit
		case opcua.DataTypeIDUInt64:
			vt = opcua.VariantTypeUInt64
			goto exit
		case opcua.DataTypeIDFloat:
			vt = opcua.VariantTypeFloat
			goto exit
		case opcua.DataTypeIDDouble:
			vt = opcua.VariantTypeDouble
			goto exit
		case opcua.DataTypeIDString:
			vt = opcua.VariantTypeString
			goto exit
		case opcua.DataTypeIDDateTime:
			vt = opcua.VariantTypeDateTime
			goto exit
		case opcua.DataTypeIDGUID:
			vt = opcua.VariantTypeGUID
			goto exit
		case opcua.DataTypeIDByteString:
			vt = opcua.VariantTypeByteString
			goto exit
		case opcua.DataTypeIDXMLElement:
			vt = opcua.VariantTypeXMLElement
			goto exit
		case opcua.DataTypeIDNodeID:
			vt = opcua.VariantTypeNodeID
			goto exit
		case opcua.DataTypeIDExpandedNodeID:
			vt = opcua.VariantTypeExpandedNodeID
			goto exit
		case opcua.DataTypeIDStatusCode:
			vt = opcua.VariantTypeStatusCode
			goto exit
		case opcua.DataTypeIDQualifiedName:
			vt = opcua.VariantTypeQualifiedName
			goto exit
		case opcua.DataTypeIDLocalizedText:
			vt = opcua.VariantTypeLocalizedText
			goto exit
		case opcua.DataTypeIDStructure:
			vt = opcua.VariantTypeExtensionObject
			goto exit
		case opcua.DataTypeIDDataValue:
			vt = opcua.VariantTypeDataValue
			goto exit
		case opcua.DataTypeIDBaseDataType:
			vt = opcua.VariantTypeVariant
			goto exit
		case opcua.DataTypeIDDiagnosticInfo:
			vt = opcua.VariantTypeDiagnosticInfo
			goto exit
		case opcua.DataTypeIDEnumeration:
			vt = opcua.VariantTypeInt32 // enum?
			goto exit
		case nil:
			vt = opcua.VariantTypeNull
			goto exit
		}
		t = m.FindSuperType(t)
	}
exit:
	m.Lock()
	m.variantTypeMap[dataType] = vt
	m.Unlock()
	return vt
}

// SetAnalogTypeBehavior sets the behavoir of a variable of type AnalogType.
func (m *NamespaceManager) SetAnalogTypeBehavior(node *VariableNode) error {
	return nil
}

// SetMultiStateValueDiscreteTypeBehavior sets the behavoir of a variable of type MultiStateValueDiscreteType.
func (m *NamespaceManager) SetMultiStateValueDiscreteTypeBehavior(node *VariableNode) error {
	enumValuesNode, ok := m.FindProperty(node, opcua.ParseQualifiedName("0:EnumValues"))
	if !ok {
		return opcua.BadNodeIDUnknown
	}
	valueAsTextNode, ok := m.FindProperty(node, opcua.ParseQualifiedName("0:ValueAsText"))
	if !ok {
		return opcua.BadNodeIDUnknown
	}
	node.SetWriteValueHandler(func(ctx context.Context, req opcua.WriteValue) opcua.StatusCode {
		var value int64
		switch v := req.Value.Value.(type) {
		case uint8:
			value = int64(v)
		case uint16:
			value = int64(v)
		case uint32:
			value = int64(v)
		case uint64:
			value = int64(v)
		case int8:
			value = int64(v)
		case int16:
			value = int64(v)
		case int32:
			value = int64(v)
		case int64:
			value = int64(v)
		case float32:
			value = int64(v)
		case float64:
			value = int64(v)
		default:
			return opcua.Good
		}
		// validate
		enumValues := toEnumValues(enumValuesNode.Value().Value.([]opcua.ExtensionObject))
		for _, ev := range enumValues {
			if ev.Value == value {
				node.SetValue(opcua.NewDataValue(req.Value.Value, req.Value.StatusCode, time.Now(), 0, time.Now(), 0))
				valueAsTextNode.SetValue(opcua.NewDataValue(ev.DisplayName, 0, time.Now(), 0, time.Now(), 0))
				break
			}
		}
		return opcua.Good
	})
	return nil
}

func toEnumValues(v []opcua.ExtensionObject) []opcua.EnumValueType {
	ret := make([]opcua.EnumValueType, len(v))
	for i, v := range v {
		ret[i] = v.(opcua.EnumValueType)
	}
	return ret
}

func (m *NamespaceManager) addNodes(nodes []Node) error {
	for _, node := range nodes {
		m.nodes[node.NodeID()] = node
	}
	// add inverse refs of added nodes
	for _, node := range nodes {
		id := node.NodeID()
		for _, r := range node.References() {
			if r.ReferenceTypeID == opcua.ReferenceTypeIDHasTypeDefinition || r.ReferenceTypeID == opcua.ReferenceTypeIDHasModellingRule {
				continue
			}
			t, ok := m.nodes[opcua.ToNodeID(r.TargetID, m.namespaces)]
			if ok {
				flag := false
				for _, tr := range t.References() {
					if tr.ReferenceTypeID == r.ReferenceTypeID && tr.IsInverse != r.IsInverse && opcua.ToNodeID(tr.TargetID, m.namespaces) == id {
						flag = true
						break
					}
				}
				if !flag {
					// log.Printf("Adding reference source: %s, target: %s, type: %s, isInverse: %t\n", t.NodeID(), id, r.ReferenceTypeID, !r.IsInverse)
					inverseRef := opcua.Reference{
						ReferenceTypeID: r.ReferenceTypeID,
						IsInverse:       !r.IsInverse,
						TargetID:        opcua.NewExpandedNodeID(id)}
					t.SetReferences(append(t.References(), inverseRef))
				}
			} else {
				log.Printf("Error finding reference target: %s\n", r.TargetID)
			}
		}
	}
	return nil
}

// AddNodes adds the nodes to the namespace.
// This method adds the inverse refs as well.
func (m *NamespaceManager) AddNodes(nodes []Node) error {
	m.Lock()
	defer m.Unlock()
	return m.addNodes(nodes)
}

// AddNode adds the node to the namespace.
// This method adds the inverse refs as well.
func (m *NamespaceManager) AddNode(node Node) error {
	m.Lock()
	defer m.Unlock()
	return m.addNodes([]Node{node})
}

// DeleteNodes removes the nodes from the namespace.
// This method removes the inverse refs as well.
func (m *NamespaceManager) DeleteNodes(nodes []Node, deleteChildren bool) error {
	m.Lock()
	children := []Node{}
	for _, node := range nodes {
		children = append(children, m.GetChildren(node, m.namespaces, hasChildandSubtypes)...)
	}
	for _, node := range children {
		m.deleteNodeandInverseReferences(node, m.namespaces)
	}
	for _, node := range nodes {
		m.deleteNodeandInverseReferences(node, m.namespaces)
	}
	m.Unlock()
	return nil
}

func (m *NamespaceManager) deleteNodeandInverseReferences(node Node, uris []string) error {
	id := node.NodeID()
	// delete inverse references from target nodes.
	for _, r := range node.References() {
		if r.ReferenceTypeID == opcua.ReferenceTypeIDHasTypeDefinition || r.ReferenceTypeID == opcua.ReferenceTypeIDHasModellingRule {
			continue
		}
		t, ok := m.nodes[opcua.ToNodeID(r.TargetID, uris)]
		if ok {
			refs := []opcua.Reference{}
			for _, tr := range t.References() {
				if tr.ReferenceTypeID == r.ReferenceTypeID && tr.IsInverse != r.IsInverse && opcua.ToNodeID(tr.TargetID, uris) == id {
					continue
				}
				refs = append(refs, tr)
			}
			t.SetReferences(refs)
			// log.Printf("Removing reference source: %s, target: %s, type: %s, isInverse: %t\n", t.NodeID(), id, r.ReferenceTypeID, !r.IsInverse)
		} else {
			log.Printf("Error finding reference target: %s\n", r.TargetID)
		}
	}
	// delete node from namespace.
	delete(m.nodes, id)
	return nil
}

// DeleteNode removes the node from the namespace.
// This method removes the inverse refs as well.
func (m *NamespaceManager) DeleteNode(node Node, deleteChildren bool) error {
	return m.DeleteNodes([]Node{node}, deleteChildren)
}

// GetSubTypes traverses the tree to get all target nodes with HasSubtype reference type.
func (m *NamespaceManager) GetSubTypes(node Node) []Node {
	children := []Node{}
	queue := deque.Deque{}
	queue.PushBack(node)
	for queue.Len() > 0 {
		node := queue.PopFront().(Node)
		for _, r := range node.References() {
			if !r.IsInverse && r.ReferenceTypeID == opcua.ReferenceTypeIDHasSubtype {
				queue.PushBack(node)
				children = append(children, node)
			}
		}
	}
	return children
}

// GetChildren traverses the tree to get all target nodes with the given reference types.
func (m *NamespaceManager) GetChildren(node Node, uris []string, withRefTypes []opcua.NodeID) []Node {
	children := []Node{}
	type queuedItem struct {
		Node    Node
		Visited bool
	}
	queue := deque.Deque{}
	queue.PushBack(queuedItem{node, false})
	for queue.Len() > 0 {
		item := queue.PopFront().(queuedItem)
		if item.Visited {
			continue
		}
		for _, r := range item.Node.References() {
			if !r.IsInverse && (withRefTypes == nil || Contains(withRefTypes, r.ReferenceTypeID)) {
				if target, ok := m.nodes[opcua.ToNodeID(r.TargetID, uris)]; ok {
					queue.PushBack(queuedItem{target, false})
					children = append(children, target)
				}
			}
		}
	}
	return children
}

// Any returns true if the given function returns true for any of the given nodes.
func Any(nodes []opcua.NodeID, f func(n opcua.NodeID) bool) bool {
	for _, n := range nodes {
		if f(n) {
			return true
		}
	}
	return false
}

// Contains returns true if the given node is found to equal any of the given nodes.
func Contains(nodes []opcua.NodeID, node opcua.NodeID) bool {
	for _, n := range nodes {
		if n == node {
			return true
		}
	}
	return false
}

// LoadNodeSetFromFile loads the UANodeSet XML from a file with the given path into the namespace.
func (m *NamespaceManager) LoadNodeSetFromFile(path string) error {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("Error reading nodeset. %s\n", err)
		return err
	}
	return m.LoadNodeSetFromBuffer(buf)
}

// LoadNodeSetFromBuffer loads the UANodeSet XML from a buffer into the namespace.
func (m *NamespaceManager) LoadNodeSetFromBuffer(buf []byte) error {
	set := &opcua.UANodeSet{}
	err := xml.Unmarshal(buf, &set)
	if err != nil {
		log.Printf("Error decoding nodeset. %s\n", err)
		return err
	}

	nsMap := make(map[uint16]uint16, 8)
	ns1 := m.NamespaceUris()

	for i, nsu := range set.NamespaceUris {
		var j uint16
		if k := indexOfString(ns1, nsu); k != -1 {
			j = uint16(k)
		} else {

			j = m.Add(nsu)
		}
		nsMap[uint16(i+1)] = j
	}

	aliases := make(map[string]string, len(set.Aliases))
	for _, a := range set.Aliases {
		aliases[a.Alias] = a.NodeID
	}

	nodes := make([]Node, len(set.Nodes))
	for i, n := range set.Nodes {
		switch n.XMLName.Local {
		case "UAObjectType":
			nodes[i] = NewObjectTypeNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.IsAbstract,
			)
		case "UAVariableType":
			nodes[i] = NewVariableTypeNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				toDataValue(n.Value, n.DataType, aliases, nsMap, toInt32(n.ValueRank, -1), m),
				toNodeID(n.NodeID, aliases, nsMap),
				toInt32(n.ValueRank, -1),
				toDims(n.ArrayDimensions, toInt32(n.ValueRank, -1)),
				n.IsAbstract,
			)
		case "UADataType":
			nodes[i] = NewDataTypeNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.IsAbstract,
			)
		case "UAReferenceType":
			nodes[i] = NewReferenceTypeNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.IsAbstract,
				n.Symmetric,
				opcua.LocalizedText{Text: n.InverseName},
			)
		case "UAObject":
			nodes[i] = NewObjectNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.EventNotifier,
			)
		case "UAVariable":
			nodes[i] = NewVariableNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				toDataValue(n.Value, n.DataType, aliases, nsMap, toInt32(n.ValueRank, -1), m),
				toNodeID(n.DataType, aliases, nsMap),
				toInt32(n.ValueRank, -1),
				toDims(n.ArrayDimensions, toInt32(n.ValueRank, -1)),
				toUint8(n.AccessLevel, 1),
				n.MinimumSamplingInterval,
				n.Historizing,
			)
		case "UAMethod":
			nodes[i] = NewMethodNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				toBool(n.Executable, true),
			)
		case "UAView":
			nodes[i] = NewViewNode(
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.ContainsNoLoops,
				n.EventNotifier,
			)
		}
	}
	err = m.AddNodes(nodes)
	if err != nil {
		log.Printf("Error adding nodes. %s\n", err)
		return err
	}
	return nil
}

func toNodeID(s string, aliases map[string]string, nsMap map[uint16]uint16) opcua.NodeID {
	if alias, exists := aliases[s]; exists {
		s = alias
	}
	var ns uint16
	if strings.HasPrefix(s, "ns=") {
		var pos = strings.Index(s, ";")
		if pos == -1 {
			return nil
		}
		if ns1, err := strconv.ParseUint(s[3:pos], 10, 16); err == nil {
			ns = uint16(ns1)
		}
		s = s[pos+1:]
		if ns2, exists := nsMap[ns]; exists {
			ns = ns2
		}
	}
	switch {
	case strings.HasPrefix(s, "i="):
		if id, err := strconv.ParseUint(s[2:], 10, 32); err == nil {
			return opcua.NewNodeIDNumeric(ns, uint32(id))
		}
		return nil
	case strings.HasPrefix(s, "s="):
		return opcua.NewNodeIDString(ns, s[2:])
	case strings.HasPrefix(s, "g="):
		if id, err := uuid.Parse(s[2:]); err == nil {
			return opcua.NewNodeIDGUID(ns, id)
		}
		return nil
	case strings.HasPrefix(s, "b="):
		if id, err := base64.StdEncoding.DecodeString(s[2:]); err == nil {
			return opcua.NewNodeIDOpaque(ns, opcua.ByteString(id))
		}
		return nil
	}
	return nil
}

func toDims(dims string, rank int32) []uint32 {
	if dims == "" {
		if rank > 0 {
			return make([]uint32, rank)
		}
		return []uint32{}
	}
	sa := strings.Split(dims, ",")
	ia := make([]uint32, len(sa))
	for i, a := range sa {
		if v, err := strconv.ParseUint(a, 10, 32); err == nil {
			ia[i] = uint32(v)
		}
	}
	return ia
}

func toRefs(refs []*opcua.UAReference, aliases map[string]string, nsMap map[uint16]uint16) []opcua.Reference {
	if len(refs) == 0 {
		return []opcua.Reference{}
	}
	ra := make([]opcua.Reference, len(refs))
	for i, r := range refs {
		ra[i] = opcua.Reference{
			ReferenceTypeID: toNodeID(r.ReferenceType, aliases, nsMap),
			IsInverse:       r.IsForward == "false",
			TargetID:        opcua.NewExpandedNodeID(toNodeID(r.TargetNodeID, aliases, nsMap)),
		}
	}
	return ra
}

func toBrowseName(s string, nsMap map[uint16]uint16) opcua.QualifiedName {
	var ns uint64
	var pos = strings.Index(s, ":")
	if pos == -1 {
		return opcua.NewQualifiedName(uint16(ns), s)
	}
	ns, err := strconv.ParseUint(s[:pos], 10, 16)
	if err != nil {
		return opcua.NewQualifiedName(uint16(ns), s)
	}
	s = s[pos+1:]
	if ns2, exists := nsMap[uint16(ns)]; exists {
		ns = uint64(ns2)
	}
	return opcua.NewQualifiedName(uint16(ns), s)
}

func toLocalizedText(s opcua.UALocalizedText) opcua.LocalizedText {
	if len(s.Text) > 0 {
		return opcua.NewLocalizedText(s.Text, s.Locale)
	}
	return opcua.NewLocalizedText(s.Content, "")
}

func indexOfString(data []string, element string) int {
	for k, e := range data {
		if element == e {
			return k
		}
	}
	return -1
}

func toInt32(s string, def int32) int32 {
	if v, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(v)
	}
	return def
}

func toUint8(s string, def uint8) uint8 {
	if v, err := strconv.ParseUint(s, 10, 8); err == nil {
		return uint8(v)
	}
	return def
}

func toBool(s string, def bool) bool {
	if v, err := strconv.ParseBool(s); err == nil {
		return v
	}
	return def
}

// func (m *NamespaceManager) isEnum(dataType string) bool {
// 	return m.IsSubtype(opcua.ParseNodeID(dataType), opcua.DataTypeIDEnumeration)
// }

func toDataValue(s opcua.UAVariant, dataType string, aliases map[string]string, nsMap map[uint16]uint16, rank int32, m *NamespaceManager) opcua.DataValue {
	if alias, exists := aliases[dataType]; exists {
		dataType = alias
	}
	now := time.Now()
	if true {
		switch rank {
		case -1:
			switch opcua.ParseNodeID(dataType) {
			case opcua.DataTypeIDBoolean:
				if s.Bool != nil {
					return opcua.NewDataValue(*s.Bool, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDByte:
				if s.Byte != nil {
					return opcua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt16:
				if s.Int16 != nil {
					return opcua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInt16:
				if s.UInt16 != nil {
					return opcua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt32:
				if s.Int32 != nil {
					return opcua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				}
				return opcua.NewDataValue(int32(0), 0, now, 0, now, 0)
			case opcua.DataTypeIDUInt32:
				if s.UInt32 != nil {
					return opcua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDSByte:
				if s.SByte != nil {
					return opcua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt64:
				if s.Int64 != nil {
					return opcua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInt64:
				if s.UInt64 != nil {
					return opcua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDFloat:
				if s.Float != nil {
					return opcua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDouble:
				if s.Double != nil {
					return opcua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDString:
				if s.String != nil {
					return opcua.NewDataValue(*s.String, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDateTime:
				if s.DateTime != nil {
					return opcua.NewDataValue(*s.DateTime, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDGUID:
				if s.GUID != nil {
					item := *s.GUID
					if g, err := uuid.Parse(item.String); err == nil {
						return opcua.NewDataValue(g, 0, now, 0, now, 0)
					}
				}
			case opcua.DataTypeIDByteString:
				if s.ByteString != nil {
					return opcua.NewDataValue(*s.ByteString, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDXMLElement:
				if s.XMLElement != nil {
					item := *s.XMLElement
					return opcua.NewDataValue(opcua.XMLElement(item.InnerXML), 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDLocalizedText:
				if s.LocalizedText != nil {
					item := *s.LocalizedText
					return opcua.NewDataValue(opcua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDQualifiedName:
				if s.QualifiedName != nil {
					item := *s.QualifiedName
					return opcua.NewDataValue(opcua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDuration:
				if s.Double != nil {
					return opcua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDNodeID:
				if s.NodeID != nil {
					item := *s.NodeID
					return opcua.NewDataValue(opcua.ParseNodeID(strings.TrimSpace(item.Identifier)), 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDExpandedNodeID:
				if s.ExpandedNodeID != nil {
					item := *s.ExpandedNodeID
					return opcua.NewDataValue(opcua.ParseExpandedNodeID(strings.TrimSpace(item.Identifier)), 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInteger:
				switch {
				case s.SByte != nil:
					return opcua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return opcua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return opcua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return opcua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInteger:
				switch {
				case s.Byte != nil:
					return opcua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return opcua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return opcua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return opcua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDNumber:
				switch {
				case s.Byte != nil:
					return opcua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return opcua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return opcua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return opcua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				case s.SByte != nil:
					return opcua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return opcua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return opcua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return opcua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				case s.Float != nil:
					return opcua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				case s.Double != nil:
					return opcua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDBaseDataType:
				switch {
				case s.Bool != nil:
					return opcua.NewDataValue(*s.Bool, 0, now, 0, now, 0)
				case s.Byte != nil:
					return opcua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return opcua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return opcua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return opcua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				case s.SByte != nil:
					return opcua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return opcua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return opcua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return opcua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				case s.Float != nil:
					return opcua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				case s.Double != nil:
					return opcua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				case s.String != nil:
					return opcua.NewDataValue(*s.String, 0, now, 0, now, 0)
				case s.DateTime != nil:
					return opcua.NewDataValue(*s.DateTime, 0, now, 0, now, 0)
				case s.GUID != nil:
					if g, err := uuid.Parse(s.GUID.String); err == nil {
						return opcua.NewDataValue(g, 0, now, 0, now, 0)
					}
				case s.ByteString != nil:
					return opcua.NewDataValue(*s.ByteString, 0, now, 0, now, 0)
				case s.XMLElement != nil:
					return opcua.NewDataValue(opcua.XMLElement(s.XMLElement.InnerXML), 0, now, 0, now, 0)
				case s.LocalizedText != nil:
					item := *s.LocalizedText
					return opcua.NewDataValue(opcua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}, 0, now, 0, now, 0)
				case s.QualifiedName != nil:
					item := *s.QualifiedName
					return opcua.NewDataValue(opcua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}, 0, now, 0, now, 0)
				case s.NodeID != nil:
					return opcua.NewDataValue(opcua.ParseNodeID(strings.TrimSpace(s.NodeID.Identifier)), 0, now, 0, now, 0)
				case s.ExpandedNodeID != nil:
					return opcua.NewDataValue(opcua.ParseExpandedNodeID(strings.TrimSpace(s.ExpandedNodeID.Identifier)), 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDRange:
				if s.ExtensionObject != nil {
					item := s.ExtensionObject.Range
					return opcua.NewDataValue(opcua.Range{Low: item.Low, High: item.High}, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDEUInformation:
				if s.ExtensionObject != nil {
					item := s.ExtensionObject.EUInformation
					return opcua.NewDataValue(opcua.EUInformation{
						NamespaceURI: item.NamespaceURI,
						UnitID:       item.UnitID,
						DisplayName:  opcua.LocalizedText{Text: item.DisplayName.Text, Locale: item.DisplayName.Locale},
						Description:  opcua.LocalizedText{Text: item.Description.Text, Locale: item.Description.Locale},
					}, 0, now, 0, now, 0)
				}
			default:
				n2 := toNodeID(dataType, aliases, nsMap)
				if m.IsSubtype(n2, opcua.DataTypeIDEnumeration) {
					if s.Int32 != nil {
						return opcua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
					}
				}
				return opcua.NewDataValue(nil, 0, now, 0, now, 0)
			}
		case 1:
			switch opcua.ParseNodeID(dataType) {
			case opcua.DataTypeIDBoolean:
				if s.ListOfBoolean != nil {
					return opcua.NewDataValue(s.ListOfBoolean.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDSByte:
				if s.ListOfSByte != nil {
					return opcua.NewDataValue(s.ListOfSByte.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDByte:
				if s.ListOfByte != nil {
					// bugfix: xml.Encoding can't decode directly into []byte
					list := s.ListOfByte.List
					list2 := make([]byte, len(list))
					for i, item := range list {
						list2[i] = byte(item)
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt16:
				if s.ListOfInt16 != nil {
					return opcua.NewDataValue(s.ListOfInt16.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInt16:
				if s.ListOfUInt16 != nil {
					return opcua.NewDataValue(s.ListOfUInt16.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt32:
				if s.ListOfInt32 != nil {
					return opcua.NewDataValue(s.ListOfInt32.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInt32:
				if s.ListOfUInt32 != nil {
					return opcua.NewDataValue(s.ListOfUInt32.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDInt64:
				if s.ListOfInt64 != nil {
					return opcua.NewDataValue(s.ListOfInt64.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDUInt64:
				if s.ListOfUInt64 != nil {
					return opcua.NewDataValue(s.ListOfUInt64.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDFloat:
				if s.ListOfFloat != nil {
					return opcua.NewDataValue(s.ListOfFloat.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDouble:
				if s.ListOfDouble != nil {
					return opcua.NewDataValue(s.ListOfDouble.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDString:
				if s.ListOfString != nil {
					return opcua.NewDataValue(s.ListOfString.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDateTime:
				if s.ListOfDateTime != nil {
					return opcua.NewDataValue(s.ListOfDateTime.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDGUID:
				if s.ListOfGUID != nil {
					list := s.ListOfGUID.List
					list2 := make([]uuid.UUID, len(list))
					for i, item := range list {
						item2, err := uuid.Parse(*item)
						if err != nil {
							log.Printf("Error decoding Guid. %s\n", err)
							return opcua.NewDataValue(nil, 0, now, 0, now, 0)
						}
						list2[i] = item2
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDByteString:
				if s.ListOfByteString != nil {
					return opcua.NewDataValue(s.ListOfByteString.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDXMLElement:
				if s.ListOfXMLElement != nil {
					list := s.ListOfXMLElement.List
					list2 := make([]opcua.XMLElement, len(list))
					for i, item := range list {
						item2 := opcua.XMLElement(item.InnerXML)
						list2[i] = item2
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDLocalizedText:
				if s.ListOfLocalizedText != nil {
					list := s.ListOfLocalizedText.List
					list2 := make([]opcua.LocalizedText, len(list))
					for i, item := range list {
						list2[i] = opcua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDQualifiedName:
				if s.ListOfQualifiedName != nil {
					list := s.ListOfQualifiedName.List
					list2 := make([]opcua.QualifiedName, len(list))
					for i, item := range list {
						list2[i] = opcua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDDuration:
				if s.ListOfDouble != nil {
					return opcua.NewDataValue(s.ListOfDouble.List, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDBaseDataType:
				if s.ListOfVariant != nil {
					list := s.ListOfVariant.List
					list2 := make([]opcua.Variant, len(list))
					for i, v := range list {
						src := v.InnerXML
						switch v.XMLName.Local {
						case "Boolean":
							dst, _ := strconv.ParseBool(strings.TrimSpace(src))
							list2[i] = dst
						case "Byte":
							dst, _ := strconv.ParseUint(strings.TrimSpace(src), 10, 8)
							list2[i] = byte(dst)
						case "UInt16":
							dst, _ := strconv.ParseUint(strings.TrimSpace(src), 10, 16)
							list2[i] = uint16(dst)
						case "UInt32":
							dst, _ := strconv.ParseUint(strings.TrimSpace(src), 10, 32)
							list2[i] = uint32(dst)
						case "UInt64":
							dst, _ := strconv.ParseUint(strings.TrimSpace(src), 10, 64)
							list2[i] = uint64(dst)
						case "SByte":
							dst, _ := strconv.ParseInt(strings.TrimSpace(src), 10, 8)
							list2[i] = int8(dst)
						case "Int16":
							dst, _ := strconv.ParseInt(strings.TrimSpace(src), 10, 16)
							list2[i] = int16(dst)
						case "Int32":
							dst, _ := strconv.ParseInt(strings.TrimSpace(src), 10, 32)
							list2[i] = int32(dst)
						case "Int64":
							dst, _ := strconv.ParseInt(strings.TrimSpace(src), 10, 64)
							list2[i] = int64(dst)
						case "Float":
							dst, _ := strconv.ParseFloat(strings.TrimSpace(src), 32)
							list2[i] = float32(dst)
						case "Double":
							dst, _ := strconv.ParseFloat(strings.TrimSpace(src), 64)
							list2[i] = float64(dst)
						case "String":
							list2[i] = src
						case "DateTime":
							dst, err := time.Parse(time.RFC3339, strings.TrimSpace(src))
							if err != nil {
								list2[i] = time.Time{}
								continue
							}
							list2[i] = dst
						case "Guid":
							dst, err := uuid.Parse(strings.TrimSpace(src))
							if err != nil {
								list2[i] = uuid.UUID{}
							}
							list2[i] = dst
						case "ByteString":
							list2[i] = opcua.ByteString(src)
						case "XMLElement":
							list2[i] = opcua.XMLElement(src)
						case "LocalizedText":
							item := &opcua.UALocalizedText{}
							hack := fmt.Sprintf("<uax:LocalizedText>%s</uax:LocalizedText>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = opcua.LocalizedText{Text: item.Text, Locale: item.Locale}
						case "QualifiedName":
							item := &opcua.UAQualifiedName{}
							hack := fmt.Sprintf("<uax:QualifiedName>%s</uax:QualifiedName>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = opcua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: item.Name}
						case "NodeID":
							list2[i] = opcua.ParseNodeID(strings.TrimSpace(src))
						case "ExpandedNodeID":
							list2[i] = opcua.ParseExpandedNodeID(strings.TrimSpace(src))
						case "ExtensionObject":
							item := &opcua.UAExtensionObject{}
							hack := fmt.Sprintf("<uax:ExtensionObject>%s</uax:ExtensionObject>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = nil
						default:
							list2[i] = nil
						}
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDArgument:
				if s.ListOfExtensionObject != nil {
					list := s.ListOfExtensionObject.List
					list2 := make([]opcua.ExtensionObject, len(list))
					for i, item := range list {
						arg := item.Argument
						list2[i] = opcua.Argument{
							Name:            arg.Name,
							DataType:        toNodeID(arg.DataType, aliases, nsMap),
							ValueRank:       toInt32(arg.ValueRank, -1),
							ArrayDimensions: toDims(arg.ArrayDimensions, toInt32(arg.ValueRank, -1)),
							Description:     opcua.LocalizedText{Text: arg.Description.Text, Locale: arg.Description.Locale},
						}
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case opcua.DataTypeIDEnumValueType:
				if s.ListOfExtensionObject != nil {
					list := s.ListOfExtensionObject.List
					list2 := make([]opcua.ExtensionObject, len(list))
					for i, item := range list {
						arg := item.EnumValueType
						list2[i] = opcua.EnumValueType{
							Value:       arg.Value,
							DisplayName: opcua.LocalizedText{Text: arg.DisplayName.Text, Locale: arg.DisplayName.Locale},
							Description: opcua.LocalizedText{Text: arg.Description.Text, Locale: arg.Description.Locale},
						}
					}
					return opcua.NewDataValue(list2, 0, now, 0, now, 0)
				}

			default:
				return opcua.NewDataValue(nil, 0, now, 0, now, 0)
			}
		default:
			return opcua.NewDataValue(nil, 0, now, 0, now, 0)
		}
	}
	return opcua.NewDataValue(nil, 0, now, 0, now, 0)
}
