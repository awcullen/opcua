package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua/ua"
)

type VariableTypeNode struct {
	sync.RWMutex
	nodeId             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	value              ua.DataValue
	dataType           ua.NodeID
	valueRank          int32
	arrayDimensions    []uint32
	isAbstract         bool
}

var _ Node = (*VariableTypeNode)(nil)

func NewVariableTypeNode(nodeId ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, value ua.DataValue, dataType ua.NodeID, valueRank int32, arrayDimensions []uint32, isAbstract bool) *VariableTypeNode {
	return &VariableTypeNode{
		nodeId:             nodeId,
		nodeClass:          ua.NodeClassVariableType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		value:              value,
		dataType:           dataType,
		valueRank:          valueRank,
		arrayDimensions:    arrayDimensions,
		isAbstract:         isAbstract,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *VariableTypeNode) NodeID() ua.NodeID {
	return n.nodeId
}

// NodeClass returns the NodeClass attribute of this node.
func (n *VariableTypeNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *VariableTypeNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *VariableTypeNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *VariableTypeNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *VariableTypeNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *VariableTypeNode) UserRolePermissions(ctx context.Context) []ua.RolePermissionType {
	filteredPermissions := []ua.RolePermissionType{}
	session, ok := ctx.Value(SessionKey).(*Session)
	if !ok {
		return filteredPermissions
	}
	roles := session.UserRoles()
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = session.Server().RolePermissions()
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
func (n *VariableTypeNode) References() []ua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *VariableTypeNode) SetReferences(value []ua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// Value returns the value of the Variable.
func (n *VariableTypeNode) Value() ua.DataValue {
	return n.value
}

// DataType returns the DataType attribute of this node.
func (n *VariableTypeNode) DataType() ua.NodeID {
	return n.dataType
}

// ValueRank returns the ValueRank attribute of this node.
func (n *VariableTypeNode) ValueRank() int32 {
	return n.valueRank
}

// ArrayDimensions returns the ArrayDimensions attribute of this node.
func (n *VariableTypeNode) ArrayDimensions() []uint32 {
	return n.arrayDimensions
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *VariableTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *VariableTypeNode) IsAttributeIDValid(attributeId uint32) bool {
	switch attributeId {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDIsAbstract, ua.AttributeIDDataType,
		ua.AttributeIDValueRank, ua.AttributeIDArrayDimensions:
		return true
	default:
		return false
	}
}
