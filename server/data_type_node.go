// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

// DataTypeNode is a Node class that describes the syntax of a variable's Value.
type DataTypeNode struct {
	sync.RWMutex
	nodeID             opcua.NodeID
	nodeClass          opcua.NodeClass
	browseName         opcua.QualifiedName
	displayName        opcua.LocalizedText
	description        opcua.LocalizedText
	rolePermissions    []opcua.RolePermissionType
	accessRestrictions uint16
	references         []opcua.Reference
	isAbstract         bool
	dataTypeDefinition interface{}
}

var _ Node = (*DataTypeNode)(nil)

// NewDataTypeNode creates a new DataTypeNode.
func NewDataTypeNode(nodeID opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, isAbstract bool) *DataTypeNode {
	return &DataTypeNode{
		nodeID:             nodeID,
		nodeClass:          opcua.NodeClassDataType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		isAbstract:         isAbstract,
		dataTypeDefinition: nil,
	}
}

//NodeID returns the NodeID attribute of this node.
func (n *DataTypeNode) NodeID() opcua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *DataTypeNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *DataTypeNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *DataTypeNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *DataTypeNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *DataTypeNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *DataTypeNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
	filteredPermissions := []opcua.RolePermissionType{}
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
func (n *DataTypeNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *DataTypeNode) SetReferences(value []opcua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *DataTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// DataTypeDefinition returns the DataTypeDefinition attribute of this node.
func (n *DataTypeNode) DataTypeDefinition() interface{} {
	return n.dataTypeDefinition
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *DataTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDIsAbstract, opcua.AttributeIDDataTypeDefinition:
		return true
	default:
		return false
	}
}
