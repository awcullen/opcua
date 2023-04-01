package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua/ua"
)

type VariableNode struct {
	sync.RWMutex
	server                  *Server
	nodeId                  ua.NodeID
	nodeClass               ua.NodeClass
	browseName              ua.QualifiedName
	displayName             ua.LocalizedText
	description             ua.LocalizedText
	rolePermissions         []ua.RolePermissionType
	accessRestrictions      uint16
	references              []ua.Reference
	value                   ua.DataValue
	dataType                ua.NodeID
	valueRank               int32
	arrayDimensions         []uint32
	accessLevel             byte
	minimumSamplingInterval float64
	historizing             bool
	historian               HistoryReadWriter
	readValueHandler        func(*Session, ua.ReadValueID) ua.DataValue
	writeValueHandler       func(*Session, ua.WriteValue) (ua.DataValue, ua.StatusCode)
}

var _ Node = (*VariableNode)(nil)

func NewVariableNode(server *Server, nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, value ua.DataValue, dataType ua.NodeID, valueRank int32, arrayDimensions []uint32, accessLevel byte, minimumSamplingInterval float64, historizing bool, historian HistoryReadWriter) *VariableNode {
	return &VariableNode{
		server:                  server,
		nodeId:                  nodeID,
		nodeClass:               ua.NodeClassVariable,
		browseName:              browseName,
		displayName:             displayName,
		description:             description,
		rolePermissions:         rolePermissions,
		accessRestrictions:      0,
		references:              references,
		value:                   value,
		dataType:                dataType,
		valueRank:               valueRank,
		arrayDimensions:         arrayDimensions,
		accessLevel:             accessLevel,
		minimumSamplingInterval: minimumSamplingInterval,
		historizing:             historizing,
		historian:               historian,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *VariableNode) NodeID() ua.NodeID {
	return n.nodeId
}

// NodeClass returns the NodeClass attribute of this node.
func (n *VariableNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *VariableNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *VariableNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *VariableNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *VariableNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *VariableNode) UserRolePermissions(userIdentity any) []ua.RolePermissionType {
	filteredPermissions := []ua.RolePermissionType{}
	roles, err := n.server.GetRoles(userIdentity, "", "")
	if err != nil {
		return filteredPermissions
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = n.server.RolePermissions()
	}
	for _, role := range roles {
		for _, rp := range rolePermissions {
			if rp.RoleID == role {
				filteredPermissions = append(filteredPermissions, rp)
			}
		}
	}
	return filteredPermissions
}

// References returns the References of this node.
func (n *VariableNode) References() []ua.Reference {
	n.RLock()
	defer n.RUnlock()
	return n.references
}

// SetReferences sets the References of this node.
func (n *VariableNode) SetReferences(value []ua.Reference) {
	n.Lock()
	defer n.Unlock()
	n.references = value
}

// Value returns the value of the Variable.
func (n *VariableNode) Value() ua.DataValue {
	n.RLock()
	defer n.RUnlock()
	return n.value
}

// SetValue sets the value of the Variable.
func (n *VariableNode) SetValue(value ua.DataValue) {
	n.Lock()
	defer n.Unlock()
	n.value = value
	if n.historizing {
		n.historian.WriteValue(context.Background(), n.nodeId, value)
	}
}

// DataType returns the DataType attribute of this node.
func (n *VariableNode) DataType() ua.NodeID {
	return n.dataType
}

// ValueRank returns the ValueRank attribute of this node.
func (n *VariableNode) ValueRank() int32 {
	return n.valueRank
}

// ArrayDimensions returns the ArrayDimensions attribute of this node.
func (n *VariableNode) ArrayDimensions() []uint32 {
	return n.arrayDimensions
}

// AccessLevel returns the AccessLevel attribute of this node.
func (n *VariableNode) AccessLevel() byte {
	return n.accessLevel
}

// UserAccessLevel returns the AccessLevel attribute of this node for this user.
func (n *VariableNode) UserAccessLevel(userIdentity any) byte {
	accessLevel := n.accessLevel
	roles, err := n.server.GetRoles(userIdentity, "", "")
	if err != nil {
		return 0
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = n.server.RolePermissions()
	}
	var currentRead, currentWrite, historyRead bool
	for _, role := range roles {
		for _, rp := range rolePermissions {
			if rp.RoleID == role {
				if rp.Permissions&ua.PermissionTypeRead != 0 {
					currentRead = true
				}
				if rp.Permissions&ua.PermissionTypeWrite != 0 {
					currentWrite = true
				}
				if rp.Permissions&ua.PermissionTypeReadHistory != 0 {
					historyRead = true
				}
			}
		}
	}
	if !currentRead {
		accessLevel &^= ua.AccessLevelsCurrentRead
	}
	if !currentWrite {
		accessLevel &^= ua.AccessLevelsCurrentWrite
	}
	if !historyRead {
		accessLevel &^= ua.AccessLevelsHistoryRead
	}
	return accessLevel
}

// MinimumSamplingInterval returns the MinimumSamplingInterval attribute of this node.
func (n *VariableNode) MinimumSamplingInterval() float64 {
	return n.minimumSamplingInterval
}

// Historizing returns the Historizing attribute of this node.
func (n *VariableNode) Historizing() bool {
	n.RLock()
	defer n.RUnlock()
	return n.historizing
}

// SetHistorizing sets the Historizing attribute of this node.
func (n *VariableNode) SetHistorizing(historizing bool) {
	n.Lock()
	defer n.Unlock()
	n.historizing = historizing
}

// SetReadValueHandler sets the ReadValueHandler of this node.
func (n *VariableNode) SetReadValueHandler(value func(*Session, ua.ReadValueID) ua.DataValue) {
	n.Lock()
	defer n.Unlock()
	n.readValueHandler = value
}

// SetWriteValueHandler sets the WriteValueHandler of this node.
func (n *VariableNode) SetWriteValueHandler(value func(*Session, ua.WriteValue) (ua.DataValue, ua.StatusCode)) {
	n.Lock()
	defer n.Unlock()
	n.writeValueHandler = value
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *VariableNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDValue, ua.AttributeIDDataType,
		ua.AttributeIDValueRank, ua.AttributeIDArrayDimensions, ua.AttributeIDAccessLevel,
		ua.AttributeIDUserAccessLevel, ua.AttributeIDMinimumSamplingInterval, ua.AttributeIDHistorizing:
		return true
	default:
		return false
	}
}
