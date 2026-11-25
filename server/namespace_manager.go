// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"slices"

	"github.com/awcullen/opcua/ua"
	"github.com/gammazero/deque"
	"github.com/google/uuid"
)

// NamespaceManager manages the namespaces for a server.
type NamespaceManager struct {
	sync.RWMutex
	server     *Server
	namespaces []string
	nodes      map[ua.NodeID]Node
}

// NewNamespaceManager instantiates a new NamespaceManager.
func NewNamespaceManager(server *Server) *NamespaceManager {
	return &NamespaceManager{
		server:     server,
		namespaces: []string{"http://opcfoundation.org/UA/", server.LocalDescription().ApplicationURI},
		nodes:      make(map[ua.NodeID]Node, 4096),
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

// FindNode returns the Node with the given NodeID from the namespace.
func (m *NamespaceManager) FindNode(id ua.NodeID) (node Node, ok bool) {
	m.RLock()
	defer m.RUnlock()
	node, ok = m.nodes[id]
	return
}

// FindObject returns the Object with the given NodeID from the namespace.
func (m *NamespaceManager) FindObject(id ua.NodeID) (node *ObjectNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*ObjectNode)
	}
	return
}

// FindVariable returns the Variable with the given NodeID from the namespace.
func (m *NamespaceManager) FindVariable(id ua.NodeID) (node *VariableNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*VariableNode)
	}
	return
}

// FindMethod returns the Method with the given NodeID from the namespace.
func (m *NamespaceManager) FindMethod(id ua.NodeID) (node *MethodNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*MethodNode)
	}
	return
}

// FindDataType returns the DataType with the given NodeID from the namespace.
func (m *NamespaceManager) FindDataType(id ua.NodeID) (node *DataTypeNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*DataTypeNode)
	}
	return
}

// FindObjectType returns the ObjectType with the given NodeID from the namespace.
func (m *NamespaceManager) FindObjectType(id ua.NodeID) (node *ObjectTypeNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*ObjectTypeNode)
	}
	return
}

// FindReferenceType returns the ReferenceType with the given NodeID from the namespace.
func (m *NamespaceManager) FindReferenceType(id ua.NodeID) (node *ReferenceTypeNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*ReferenceTypeNode)
	}
	return
}

// FindVariableType returns the VariableType with the given NodeID from the namespace.
func (m *NamespaceManager) FindVariableType(id ua.NodeID) (node *VariableTypeNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if node1, ok1 := m.nodes[id]; ok1 {
		node, ok = node1.(*VariableTypeNode)
	}
	return
}

// FindProperty returns the property with the given browseName from the namespace.
func (m *NamespaceManager) FindProperty(startNode Node, browseName ua.QualifiedName) (node *VariableNode, ok bool) {
	m.RLock()
	defer m.RUnlock()
	for _, r := range startNode.References() {
		if !r.IsInverse && ua.ReferenceTypeIDHasProperty == r.ReferenceTypeID {
			id := ua.ToNodeID(r.TargetID, m.namespaces)
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
func (m *NamespaceManager) FindComponent(startNode Node, browseName ua.QualifiedName) (node Node, ok bool) {
	m.RLock()
	defer m.RUnlock()
	for _, r := range startNode.References() {
		if !r.IsInverse && ua.ReferenceTypeIDHasComponent == r.ReferenceTypeID {
			id := ua.ToNodeID(r.TargetID, m.namespaces)
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

// IsSubtype returns whether the given subtype is derived from the given supertype.
func (m *NamespaceManager) IsSubtype(subtype, supertype ua.NodeID) bool {
	m.RLock()
	defer m.RUnlock()
	id := subtype
loop:
	if n, ok := m.nodes[id]; ok {
		for _, r := range n.References() {
			if r.IsInverse && ua.ReferenceTypeIDHasSubtype == r.ReferenceTypeID {
				id = ua.ToNodeID(r.TargetID, m.NamespaceUris())
				if supertype == id {
					return true
				}
				goto loop
			}
		}
	}
	return false
}

// FindSuperType returns the supertype of the given subtype.
func (m *NamespaceManager) FindSuperType(subType ua.NodeID) (superType ua.NodeID, ok bool) {
	m.RLock()
	defer m.RUnlock()
	if n, ok := m.nodes[subType]; ok {
		for _, r := range n.References() {
			if r.IsInverse && ua.ReferenceTypeIDHasSubtype == r.ReferenceTypeID {
				return ua.ToNodeID(r.TargetID, m.NamespaceUris()), true
			}
		}
	}
	return nil, false
}

var (
	variantTypeMap = map[ua.NodeID]byte{
		ua.DataTypeIDBoolean:        ua.VariantTypeBoolean,
		ua.DataTypeIDSByte:          ua.VariantTypeSByte,
		ua.DataTypeIDByte:           ua.VariantTypeByte,
		ua.DataTypeIDInt16:          ua.VariantTypeInt16,
		ua.DataTypeIDUInt16:         ua.VariantTypeUInt16,
		ua.DataTypeIDInt32:          ua.VariantTypeInt32,
		ua.DataTypeIDUInt32:         ua.VariantTypeUInt32,
		ua.DataTypeIDInt64:          ua.VariantTypeInt64,
		ua.DataTypeIDUInt64:         ua.VariantTypeUInt64,
		ua.DataTypeIDFloat:          ua.VariantTypeFloat,
		ua.DataTypeIDDouble:         ua.VariantTypeDouble,
		ua.DataTypeIDString:         ua.VariantTypeString,
		ua.DataTypeIDDateTime:       ua.VariantTypeDateTime,
		ua.DataTypeIDGUID:           ua.VariantTypeGUID,
		ua.DataTypeIDByteString:     ua.VariantTypeByteString,
		ua.DataTypeIDXMLElement:     ua.VariantTypeXMLElement,
		ua.DataTypeIDNodeID:         ua.VariantTypeNodeID,
		ua.DataTypeIDExpandedNodeID: ua.VariantTypeExpandedNodeID,
		ua.DataTypeIDStatusCode:     ua.VariantTypeStatusCode,
		ua.DataTypeIDQualifiedName:  ua.VariantTypeQualifiedName,
		ua.DataTypeIDLocalizedText:  ua.VariantTypeLocalizedText,
		ua.DataTypeIDStructure:      ua.VariantTypeExtensionObject,
		ua.DataTypeIDDataValue:      ua.VariantTypeDataValue,
		ua.DataTypeIDBaseDataType:   ua.VariantTypeVariant,
		ua.DataTypeIDDiagnosticInfo: ua.VariantTypeDiagnosticInfo,
		ua.DataTypeIDEnumeration:    ua.VariantTypeInt32,
	}
)

// FindVariantType returns the VariantType enumeration for the given DataType.
func (m *NamespaceManager) FindVariantType(dataType ua.NodeID) (variantType byte, ok bool) {
	dataType1, ok1 := dataType, true
	for {
		variantType, ok = variantTypeMap[dataType1]
		if ok {
			return
		}
		dataType1, ok1 = m.FindSuperType(dataType1)
		if !ok1 {
			return
		}
	}
}

// SetAnalogTypeBehavior sets the behavoir of a variable of type AnalogType.
func (m *NamespaceManager) SetAnalogTypeBehavior(node *VariableNode) error {
	return nil
}

// SetMultiStateValueDiscreteTypeBehavior sets the behavoir of a variable of type MultiStateValueDiscreteType.
func (m *NamespaceManager) SetMultiStateValueDiscreteTypeBehavior(node *VariableNode) error {
	enumValuesNode, ok := m.FindProperty(node, ua.ParseQualifiedName("0:EnumValues"))
	if !ok {
		return ua.BadNodeIDUnknown
	}
	valueAsTextNode, ok := m.FindProperty(node, ua.ParseQualifiedName("0:ValueAsText"))
	if !ok {
		return ua.BadNodeIDUnknown
	}
	node.SetWriteValueHandler(func(session *Session, req ua.WriteValue) (ua.DataValue, ua.StatusCode) {
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
			return req.Value, ua.Good
		}
		// validate
		enumValues := toEnumValues(enumValuesNode.Value().Value.([]ua.ExtensionObject))
		for _, ev := range enumValues {
			if ev.Value == value {
				node.SetValue(ua.NewDataValue(req.Value.Value, req.Value.StatusCode, time.Now(), 0, time.Now(), 0))
				valueAsTextNode.SetValue(ua.NewDataValue(ev.DisplayName, 0, time.Now(), 0, time.Now(), 0))
				break
			}
		}
		return req.Value, ua.Good
	})
	return nil
}

func toEnumValues(v []ua.ExtensionObject) []ua.EnumValueType {
	ret := make([]ua.EnumValueType, len(v))
	for i, v := range v {
		ret[i] = v.(ua.EnumValueType)
	}
	return ret
}

// AddNodes adds the nodes to the namespace.
// This method also adds the inverse references.
func (m *NamespaceManager) AddNodes(nodes ...Node) error {
	m.Lock()
	defer m.Unlock()
	// first, add all nodes to namespace
	for _, node := range nodes {
		m.nodes[node.NodeID()] = node
	}
	// then, add all the inverse references
	for _, node := range nodes {
		id := node.NodeID()
		// for each reference
		for _, r := range node.References() {
			if r.ReferenceTypeID == ua.ReferenceTypeIDHasTypeDefinition || r.ReferenceTypeID == ua.ReferenceTypeIDHasModellingRule {
				continue
			}
			// if target node exists
			if t, ok := m.nodes[ua.ToNodeID(r.TargetID, m.namespaces)]; ok {
				// check if inverse reference exists
				flag := false
				for _, tr := range t.References() {
					if tr.ReferenceTypeID == r.ReferenceTypeID && tr.IsInverse != r.IsInverse && ua.ToNodeID(tr.TargetID, m.namespaces) == id {
						flag = true
						break
					}
				}
				// if inverse reference does not exist, add it
				if !flag {
					// log.Printf("Adding reference source: %s, target: %s, type: %s, isInverse: %t\n", t.NodeID(), id, r.ReferenceTypeID, !r.IsInverse)
					inverseRef := ua.Reference{
						ReferenceTypeID: r.ReferenceTypeID,
						IsInverse:       !r.IsInverse,
						TargetID:        ua.NewExpandedNodeID(id)}
					t.SetReferences(append(t.References(), inverseRef))
				}
			} else {
				log.Printf("Error finding reference target: %s\n", r.TargetID)
			}
		}
	}
	return nil
}

// isProtectedNode checks if a node should be protected from deletion.
// Protected nodes include nodes from OPC Foundation.
func isProtectedNode(id ua.NodeID) bool {
	// check if nodeID has NamespaceIndex == 0 (from OPC Foundation)
	if id != nil {
		switch v := id.(type) {
		case ua.NodeIDNumeric:
			if v.NamespaceIndex == 0 {
				return true
			}
		case ua.NodeIDString:
			if v.NamespaceIndex == 0 {
				return true
			}
		case ua.NodeIDGUID:
			if v.NamespaceIndex == 0 {
				return true
			}
		case ua.NodeIDOpaque:
			if v.NamespaceIndex == 0 {
				return true
			}
		}
	}
	return false
}

// DeleteNodes removes the given nodes from the namespace.
// This method also removes the inverse references and any child nodes. (HasChild reference subtypes)
func (m *NamespaceManager) DeleteNodes(nodes ...ua.NodeID) error {
	m.Lock()
	defer m.Unlock()
	// build slice of HasChild reference subtypes
	hasChildSubtypes := []ua.NodeID{}
	queue := deque.Deque[ua.NodeID]{}
	queue.PushBack(ua.ReferenceTypeIDHasChild)
	{
		for queue.Len() > 0 {
			if node, ok := m.nodes[queue.PopFront()]; ok {
				for _, r := range node.References() {
					if !r.IsInverse && r.ReferenceTypeID == ua.ReferenceTypeIDHasSubtype {
						target := ua.ToNodeID(r.TargetID, m.namespaces)
						queue.PushBack(target)
						hasChildSubtypes = append(hasChildSubtypes, target)
					}
				}
			}
		}
	}
	for _, id := range nodes {
		// check if node exists in namespace
		node, ok := m.nodes[id]
		if !ok {
			continue
		}
		// check if node is protected
		if isProtectedNode(id) {
			continue
		}
		// build slice of children nodes
		children := []ua.NodeID{}
		queue.PushBack(id)
		for queue.Len() > 0 {
			if node, ok := m.nodes[queue.PopFront()]; ok {
				for _, r := range node.References() {
					if !r.IsInverse && slices.Contains(hasChildSubtypes, r.ReferenceTypeID) {
						target := ua.ToNodeID(r.TargetID, m.namespaces)
						queue.PushBack(target)
						children = append(children, target)
					}
				}
			}
		}
		for _, id := range children {
			// check if child exists in namespace
			child, ok := m.nodes[id]
			if !ok {
				continue
			}
			// check if node is protected
			if isProtectedNode(id) {
				continue
			}
			// delete inverse references to node
			for _, r := range child.References() {
				if r.ReferenceTypeID == ua.ReferenceTypeIDHasTypeDefinition || r.ReferenceTypeID == ua.ReferenceTypeIDHasModellingRule {
					continue
				}
				if target, ok := m.nodes[ua.ToNodeID(r.TargetID, m.namespaces)]; ok {
					refs := []ua.Reference{}
					for _, tr := range target.References() {
						if tr.ReferenceTypeID == r.ReferenceTypeID && tr.IsInverse != r.IsInverse && ua.ToNodeID(tr.TargetID, m.namespaces) == id {
							continue
						}
						refs = append(refs, tr)
					}
					target.SetReferences(refs)
					// log.Printf("Removing reference source: %s, target: %s, type: %s, isInverse: %t\n", t.NodeID(), id, r.ReferenceTypeID, !r.IsInverse)
				} else {
					log.Printf("Error finding reference target: %s\n", r.TargetID)
				}
			}
			// finally, delete node from namespace
			delete(m.nodes, id)
		}

		// delete inverse references to node
		for _, r := range node.References() {
			if r.ReferenceTypeID == ua.ReferenceTypeIDHasTypeDefinition || r.ReferenceTypeID == ua.ReferenceTypeIDHasModellingRule {
				continue
			}
			if target, ok := m.nodes[ua.ToNodeID(r.TargetID, m.namespaces)]; ok {
				refs := []ua.Reference{}
				for _, tr := range target.References() {
					if tr.ReferenceTypeID == r.ReferenceTypeID && tr.IsInverse != r.IsInverse && ua.ToNodeID(tr.TargetID, m.namespaces) == id {
						continue
					}
					refs = append(refs, tr)
				}
				target.SetReferences(refs)
				// log.Printf("Removing reference source: %s, target: %s, type: %s, isInverse: %t\n", t.NodeID(), id, r.ReferenceTypeID, !r.IsInverse)
			} else {
				log.Printf("Error finding reference target: %s\n", r.TargetID)
			}
		}
		// finally, delete node from namespace
		delete(m.nodes, id)
	}
	return nil
}

// GetSubTypes returns all subtypes of the given node. (HasSubtype references)
func (m *NamespaceManager) GetSubTypes(nodeID ua.NodeID) []ua.NodeID {
	m.RLock()
	defer m.RUnlock()
	subTypes := []ua.NodeID{}
	queue := deque.Deque[ua.NodeID]{}
	queue.PushBack(nodeID)
	for queue.Len() > 0 {
		if node, ok := m.nodes[queue.PopFront()]; ok {
			for _, r := range node.References() {
				if !r.IsInverse && r.ReferenceTypeID == ua.ReferenceTypeIDHasSubtype {
					target := ua.ToNodeID(r.TargetID, m.namespaces)
					queue.PushBack(target)
					subTypes = append(subTypes, target)
				}
			}
		}
	}
	return subTypes
}

// GetChildren returns all children of the given parent node. (HasChild reference subtypes)
func (m *NamespaceManager) GetChildren(parentID ua.NodeID) []ua.NodeID {
	m.RLock()
	defer m.RUnlock()
	// build slice of HasChild reference subtypes
	hasChildSubtypes := []ua.NodeID{}
	queue := deque.Deque[ua.NodeID]{}
	queue.PushBack(ua.ReferenceTypeIDHasChild)
	{
		for queue.Len() > 0 {
			if node, ok := m.nodes[queue.PopFront()]; ok {
				for _, r := range node.References() {
					if !r.IsInverse && r.ReferenceTypeID == ua.ReferenceTypeIDHasSubtype {
						target := ua.ToNodeID(r.TargetID, m.namespaces)
						queue.PushBack(target)
						hasChildSubtypes = append(hasChildSubtypes, target)
					}
				}
			}
		}
	}
	// build slice of children nodes
	children := []ua.NodeID{}
	queue.PushBack(parentID)
	for queue.Len() > 0 {
		if node, ok := m.nodes[queue.PopFront()]; ok {
			for _, r := range node.References() {
				if !r.IsInverse && slices.Contains(hasChildSubtypes, r.ReferenceTypeID) {
					target := ua.ToNodeID(r.TargetID, m.namespaces)
					queue.PushBack(target)
					children = append(children, target)
				}
			}
		}
	}
	return children
}

// GetComponents returns all components of the given object node. (HasComponent references and subtypes)
func (m *NamespaceManager) GetComponents(objectID ua.NodeID) []ua.NodeID {
	m.RLock()
	defer m.RUnlock()
	// build slice of HasComponent reference subtypes
	hasComponentandSubtypes := []ua.NodeID{}
	queue := deque.Deque[ua.NodeID]{}
	queue.PushBack(ua.ReferenceTypeIDHasComponent)
	hasComponentandSubtypes = append(hasComponentandSubtypes, ua.ReferenceTypeIDHasComponent)
	{
		for queue.Len() > 0 {
			if node, ok := m.nodes[queue.PopFront()]; ok {
				for _, r := range node.References() {
					if !r.IsInverse && r.ReferenceTypeID == ua.ReferenceTypeIDHasSubtype {
						target := ua.ToNodeID(r.TargetID, m.namespaces)
						queue.PushBack(target)
						hasComponentandSubtypes = append(hasComponentandSubtypes, target)
					}
				}
			}
		}
	}
	components := []ua.NodeID{}
	queue.PushBack(objectID)
	for queue.Len() > 0 {
		if node, ok := m.nodes[queue.PopFront()]; ok {
			for _, r := range node.References() {
				if !r.IsInverse && slices.Contains(hasComponentandSubtypes, r.ReferenceTypeID) {
					target := ua.ToNodeID(r.TargetID, m.namespaces)
					queue.PushBack(target)
					components = append(components, target)
				}
			}
		}
	}
	return components
}

// OnEvent raises the event, starting from the target node, follows HasNotifier references until the Server node.
func (m *NamespaceManager) OnEvent(target *ObjectNode, evt ua.Event) error {
	for target.nodeID != ua.ObjectIDServer {
		target.OnEvent(evt)
		found := false
		for _, r := range target.References() {
			if r.IsInverse && r.ReferenceTypeID == ua.ReferenceTypeIDHasNotifier {
				if target1, ok1 := m.FindObject(ua.ToNodeID(r.TargetID, m.NamespaceUris())); ok1 {
					found = true
					target = target1
					break
				}
				return ua.BadNodeIDUnknown
			}
		}
		if !found {
			return nil
		}
	}
	target.OnEvent(evt)
	return nil
}

// LoadNodeSetFromFile loads the UANodeSet XML from a file with the given path into the namespace.
func (m *NamespaceManager) LoadNodeSetFromFile(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading nodeset. %s\n", err)
		return err
	}
	return m.LoadNodeSetFromBuffer(buf)
}

// LoadNodeSetFromBuffer loads the UANodeSet XML from a buffer into the namespace.
func (m *NamespaceManager) LoadNodeSetFromBuffer(buf []byte) error {
	srv := m.server
	set := &ua.UANodeSet{}
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
				srv,
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
				srv,
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
				n.IsAbstract,
			)
		case "UADataType":
			nodes[i] = NewDataTypeNode(
				srv,
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.IsAbstract,
				nil,
			)
		case "UAReferenceType":
			nodes[i] = NewReferenceTypeNode(
				srv,
				toNodeID(n.NodeID, aliases, nsMap),
				toBrowseName(n.BrowseName, nsMap),
				toLocalizedText(n.DisplayName),
				toLocalizedText(n.Description),
				nil,
				toRefs(n.References, aliases, nsMap),
				n.IsAbstract,
				n.Symmetric,
				ua.LocalizedText{Text: n.InverseName},
			)
		case "UAObject":
			nodes[i] = NewObjectNode(
				srv,
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
				srv,
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
				m.server.historian,
			)
		case "UAMethod":
			nodes[i] = NewMethodNode(
				srv,
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
				srv,
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
	if err = m.AddNodes(nodes...); err != nil {
		log.Printf("Error adding nodes. %s\n", err)
		return err
	}
	return nil
}

func toNodeID(s string, aliases map[string]string, nsMap map[uint16]uint16) ua.NodeID {
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
			return ua.NewNodeIDNumeric(ns, uint32(id))
		}
		return nil
	case strings.HasPrefix(s, "s="):
		return ua.NewNodeIDString(ns, s[2:])
	case strings.HasPrefix(s, "g="):
		if id, err := uuid.Parse(s[2:]); err == nil {
			return ua.NewNodeIDGUID(ns, id)
		}
		return nil
	case strings.HasPrefix(s, "b="):
		if id, err := base64.StdEncoding.DecodeString(s[2:]); err == nil {
			return ua.NewNodeIDOpaque(ns, ua.ByteString(id))
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

func toRefs(refs []*ua.UAReference, aliases map[string]string, nsMap map[uint16]uint16) []ua.Reference {
	if len(refs) == 0 {
		return []ua.Reference{}
	}
	ra := make([]ua.Reference, len(refs))
	for i, r := range refs {
		ra[i] = ua.Reference{
			ReferenceTypeID: toNodeID(r.ReferenceType, aliases, nsMap),
			IsInverse:       r.IsForward == "false",
			TargetID:        ua.NewExpandedNodeID(toNodeID(r.TargetNodeID, aliases, nsMap)),
		}
	}
	return ra
}

func toBrowseName(s string, nsMap map[uint16]uint16) ua.QualifiedName {
	var ns uint64
	var pos = strings.Index(s, ":")
	if pos == -1 {
		return ua.NewQualifiedName(uint16(ns), s)
	}
	ns, err := strconv.ParseUint(s[:pos], 10, 16)
	if err != nil {
		return ua.NewQualifiedName(uint16(ns), s)
	}
	s = s[pos+1:]
	if ns2, exists := nsMap[uint16(ns)]; exists {
		ns = uint64(ns2)
	}
	return ua.NewQualifiedName(uint16(ns), s)
}

func toLocalizedText(s ua.UALocalizedText) ua.LocalizedText {
	if len(s.Text) > 0 {
		return ua.NewLocalizedText(s.Text, s.Locale)
	}
	return ua.NewLocalizedText(s.Content, "")
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
// 	return m.IsSubtype(ua.ParseNodeID(dataType), ua.DataTypeIDEnumeration)
// }

func toDataValue(s ua.UAVariant, dataType string, aliases map[string]string, nsMap map[uint16]uint16, rank int32, m *NamespaceManager) ua.DataValue {
	if alias, exists := aliases[dataType]; exists {
		dataType = alias
	}
	now := time.Now()
	if true {
		switch rank {
		case -1:
			switch ua.ParseNodeID(dataType) {
			case ua.DataTypeIDBoolean:
				if s.Bool != nil {
					return ua.NewDataValue(*s.Bool, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDByte:
				if s.Byte != nil {
					return ua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt16:
				if s.Int16 != nil {
					return ua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInt16:
				if s.UInt16 != nil {
					return ua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt32:
				if s.Int32 != nil {
					return ua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				}
				return ua.NewDataValue(int32(0), 0, now, 0, now, 0)
			case ua.DataTypeIDUInt32:
				if s.UInt32 != nil {
					return ua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDSByte:
				if s.SByte != nil {
					return ua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt64:
				if s.Int64 != nil {
					return ua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInt64:
				if s.UInt64 != nil {
					return ua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDFloat:
				if s.Float != nil {
					return ua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDouble:
				if s.Double != nil {
					return ua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDString:
				if s.String != nil {
					return ua.NewDataValue(*s.String, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDateTime:
				if s.DateTime != nil {
					return ua.NewDataValue(*s.DateTime, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDGUID:
				if s.GUID != nil {
					item := *s.GUID
					if g, err := uuid.Parse(item.String); err == nil {
						return ua.NewDataValue(g, 0, now, 0, now, 0)
					}
				}
			case ua.DataTypeIDByteString:
				if s.ByteString != nil {
					return ua.NewDataValue(*s.ByteString, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDXMLElement:
				if s.XMLElement != nil {
					item := *s.XMLElement
					return ua.NewDataValue(ua.XMLElement(item.InnerXML), 0, now, 0, now, 0)
				}
			case ua.DataTypeIDLocalizedText:
				if s.LocalizedText != nil {
					item := *s.LocalizedText
					return ua.NewDataValue(ua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDQualifiedName:
				if s.QualifiedName != nil {
					item := *s.QualifiedName
					return ua.NewDataValue(ua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDuration:
				if s.Double != nil {
					return ua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDNodeID:
				if s.NodeID != nil {
					item := *s.NodeID
					return ua.NewDataValue(ua.ParseNodeID(strings.TrimSpace(item.Identifier)), 0, now, 0, now, 0)
				}
			case ua.DataTypeIDExpandedNodeID:
				if s.ExpandedNodeID != nil {
					item := *s.ExpandedNodeID
					return ua.NewDataValue(ua.ParseExpandedNodeID(strings.TrimSpace(item.Identifier)), 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInteger:
				switch {
				case s.SByte != nil:
					return ua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return ua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return ua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return ua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInteger:
				switch {
				case s.Byte != nil:
					return ua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return ua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return ua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return ua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDNumber:
				switch {
				case s.Byte != nil:
					return ua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return ua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return ua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return ua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				case s.SByte != nil:
					return ua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return ua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return ua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return ua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				case s.Float != nil:
					return ua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				case s.Double != nil:
					return ua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDBaseDataType:
				switch {
				case s.Bool != nil:
					return ua.NewDataValue(*s.Bool, 0, now, 0, now, 0)
				case s.Byte != nil:
					return ua.NewDataValue(*s.Byte, 0, now, 0, now, 0)
				case s.UInt16 != nil:
					return ua.NewDataValue(*s.UInt16, 0, now, 0, now, 0)
				case s.UInt32 != nil:
					return ua.NewDataValue(*s.UInt32, 0, now, 0, now, 0)
				case s.UInt64 != nil:
					return ua.NewDataValue(*s.UInt64, 0, now, 0, now, 0)
				case s.SByte != nil:
					return ua.NewDataValue(*s.SByte, 0, now, 0, now, 0)
				case s.Int16 != nil:
					return ua.NewDataValue(*s.Int16, 0, now, 0, now, 0)
				case s.Int32 != nil:
					return ua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
				case s.Int64 != nil:
					return ua.NewDataValue(*s.Int64, 0, now, 0, now, 0)
				case s.Float != nil:
					return ua.NewDataValue(*s.Float, 0, now, 0, now, 0)
				case s.Double != nil:
					return ua.NewDataValue(*s.Double, 0, now, 0, now, 0)
				case s.String != nil:
					return ua.NewDataValue(*s.String, 0, now, 0, now, 0)
				case s.DateTime != nil:
					return ua.NewDataValue(*s.DateTime, 0, now, 0, now, 0)
				case s.GUID != nil:
					if g, err := uuid.Parse(s.GUID.String); err == nil {
						return ua.NewDataValue(g, 0, now, 0, now, 0)
					}
				case s.ByteString != nil:
					return ua.NewDataValue(*s.ByteString, 0, now, 0, now, 0)
				case s.XMLElement != nil:
					return ua.NewDataValue(ua.XMLElement(s.XMLElement.InnerXML), 0, now, 0, now, 0)
				case s.LocalizedText != nil:
					item := *s.LocalizedText
					return ua.NewDataValue(ua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}, 0, now, 0, now, 0)
				case s.QualifiedName != nil:
					item := *s.QualifiedName
					return ua.NewDataValue(ua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}, 0, now, 0, now, 0)
				case s.NodeID != nil:
					return ua.NewDataValue(ua.ParseNodeID(strings.TrimSpace(s.NodeID.Identifier)), 0, now, 0, now, 0)
				case s.ExpandedNodeID != nil:
					return ua.NewDataValue(ua.ParseExpandedNodeID(strings.TrimSpace(s.ExpandedNodeID.Identifier)), 0, now, 0, now, 0)
				}
			case ua.DataTypeIDRange:
				if s.ExtensionObject != nil {
					item := s.ExtensionObject.Range
					return ua.NewDataValue(ua.Range{Low: item.Low, High: item.High}, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDEUInformation:
				if s.ExtensionObject != nil {
					item := s.ExtensionObject.EUInformation
					return ua.NewDataValue(ua.EUInformation{
						NamespaceURI: item.NamespaceURI,
						UnitID:       item.UnitID,
						DisplayName:  ua.LocalizedText{Text: item.DisplayName.Text, Locale: item.DisplayName.Locale},
						Description:  ua.LocalizedText{Text: item.Description.Text, Locale: item.Description.Locale},
					}, 0, now, 0, now, 0)
				}
			default:
				n2 := toNodeID(dataType, aliases, nsMap)
				if m.IsSubtype(n2, ua.DataTypeIDEnumeration) {
					if s.Int32 != nil {
						return ua.NewDataValue(*s.Int32, 0, now, 0, now, 0)
					}
				}
				return ua.NewDataValue(nil, 0, now, 0, now, 0)
			}
		case 1:
			switch ua.ParseNodeID(dataType) {
			case ua.DataTypeIDBoolean:
				if s.ListOfBoolean != nil {
					return ua.NewDataValue(s.ListOfBoolean.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDSByte:
				if s.ListOfSByte != nil {
					return ua.NewDataValue(s.ListOfSByte.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDByte:
				if s.ListOfByte != nil {
					// bugfix: xml.Encoding can't decode directly into []byte
					list := s.ListOfByte.List
					list2 := make([]byte, len(list))
					for i, item := range list {
						list2[i] = byte(item)
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt16:
				if s.ListOfInt16 != nil {
					return ua.NewDataValue(s.ListOfInt16.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInt16:
				if s.ListOfUInt16 != nil {
					return ua.NewDataValue(s.ListOfUInt16.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt32:
				if s.ListOfInt32 != nil {
					return ua.NewDataValue(s.ListOfInt32.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInt32:
				if s.ListOfUInt32 != nil {
					return ua.NewDataValue(s.ListOfUInt32.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDInt64:
				if s.ListOfInt64 != nil {
					return ua.NewDataValue(s.ListOfInt64.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDUInt64:
				if s.ListOfUInt64 != nil {
					return ua.NewDataValue(s.ListOfUInt64.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDFloat:
				if s.ListOfFloat != nil {
					return ua.NewDataValue(s.ListOfFloat.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDouble:
				if s.ListOfDouble != nil {
					return ua.NewDataValue(s.ListOfDouble.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDString:
				if s.ListOfString != nil {
					return ua.NewDataValue(s.ListOfString.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDateTime:
				if s.ListOfDateTime != nil {
					return ua.NewDataValue(s.ListOfDateTime.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDGUID:
				if s.ListOfGUID != nil {
					list := s.ListOfGUID.List
					list2 := make([]uuid.UUID, len(list))
					for i, item := range list {
						item2, err := uuid.Parse(*item)
						if err != nil {
							log.Printf("Error decoding Guid. %s\n", err)
							return ua.NewDataValue(nil, 0, now, 0, now, 0)
						}
						list2[i] = item2
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDByteString:
				if s.ListOfByteString != nil {
					return ua.NewDataValue(s.ListOfByteString.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDXMLElement:
				if s.ListOfXMLElement != nil {
					list := s.ListOfXMLElement.List
					list2 := make([]ua.XMLElement, len(list))
					for i, item := range list {
						item2 := ua.XMLElement(item.InnerXML)
						list2[i] = item2
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDLocalizedText:
				if s.ListOfLocalizedText != nil {
					list := s.ListOfLocalizedText.List
					list2 := make([]ua.LocalizedText, len(list))
					for i, item := range list {
						list2[i] = ua.LocalizedText{Text: strings.TrimSpace(item.Text), Locale: strings.TrimSpace(item.Locale)}
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDQualifiedName:
				if s.ListOfQualifiedName != nil {
					list := s.ListOfQualifiedName.List
					list2 := make([]ua.QualifiedName, len(list))
					for i, item := range list {
						list2[i] = ua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: strings.TrimSpace(item.Name)}
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDDuration:
				if s.ListOfDouble != nil {
					return ua.NewDataValue(s.ListOfDouble.List, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDBaseDataType:
				if s.ListOfVariant != nil {
					list := s.ListOfVariant.List
					list2 := make([]ua.Variant, len(list))
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
							list2[i] = ua.ByteString(src)
						case "XMLElement":
							list2[i] = ua.XMLElement(src)
						case "LocalizedText":
							item := &ua.UALocalizedText{}
							hack := fmt.Sprintf("<uax:LocalizedText>%s</uax:LocalizedText>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = ua.LocalizedText{Text: item.Text, Locale: item.Locale}
						case "QualifiedName":
							item := &ua.UAQualifiedName{}
							hack := fmt.Sprintf("<uax:QualifiedName>%s</uax:QualifiedName>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = ua.QualifiedName{NamespaceIndex: item.NamespaceIndex, Name: item.Name}
						case "NodeID":
							list2[i] = ua.ParseNodeID(strings.TrimSpace(src))
						case "ExpandedNodeID":
							list2[i] = ua.ParseExpandedNodeID(strings.TrimSpace(src))
						case "ExtensionObject":
							item := &ua.UAExtensionObject{}
							hack := fmt.Sprintf("<uax:ExtensionObject>%s</uax:ExtensionObject>", src)
							xml.Unmarshal([]byte(hack), item)
							list2[i] = nil
						default:
							list2[i] = nil
						}
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDArgument:
				if s.ListOfExtensionObject != nil {
					list := s.ListOfExtensionObject.List
					list2 := make([]ua.ExtensionObject, len(list))
					for i, item := range list {
						arg := item.Argument
						list2[i] = ua.Argument{
							Name:            arg.Name,
							DataType:        toNodeID(arg.DataType, aliases, nsMap),
							ValueRank:       toInt32(arg.ValueRank, -1),
							ArrayDimensions: toDims(arg.ArrayDimensions, toInt32(arg.ValueRank, -1)),
							Description:     ua.LocalizedText{Text: arg.Description.Text, Locale: arg.Description.Locale},
						}
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}
			case ua.DataTypeIDEnumValueType:
				if s.ListOfExtensionObject != nil {
					list := s.ListOfExtensionObject.List
					list2 := make([]ua.ExtensionObject, len(list))
					for i, item := range list {
						arg := item.EnumValueType
						list2[i] = ua.EnumValueType{
							Value:       arg.Value,
							DisplayName: ua.LocalizedText{Text: arg.DisplayName.Text, Locale: arg.DisplayName.Locale},
							Description: ua.LocalizedText{Text: arg.Description.Text, Locale: arg.Description.Locale},
						}
					}
					return ua.NewDataValue(list2, 0, now, 0, now, 0)
				}

			default:
				return ua.NewDataValue(nil, 0, now, 0, now, 0)
			}
		default:
			return ua.NewDataValue(nil, 0, now, 0, now, 0)
		}
	}
	return ua.NewDataValue(nil, 0, now, 0, now, 0)
}
