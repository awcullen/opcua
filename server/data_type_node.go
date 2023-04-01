// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync"

	"github.com/awcullen/opcua/ua"
)

// DataTypeNode is a Node class that describes the syntax of a variable's Value.
type DataTypeNode struct {
	sync.RWMutex
	server             *Server
	nodeID             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	isAbstract         bool
	dataTypeDefinition any
}

var _ Node = (*DataTypeNode)(nil)

// NewDataTypeNode creates a new DataTypeNode.
func NewDataTypeNode(server *Server, nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, isAbstract bool, structureOrEnumDefinition any) *DataTypeNode {
	return &DataTypeNode{
		server:             server,
		nodeID:             nodeID,
		nodeClass:          ua.NodeClassDataType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		isAbstract:         isAbstract,
		dataTypeDefinition: structureOrEnumDefinition,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *DataTypeNode) NodeID() ua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *DataTypeNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *DataTypeNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *DataTypeNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *DataTypeNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *DataTypeNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *DataTypeNode) UserRolePermissions(userIdentity any) []ua.RolePermissionType {
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
func (n *DataTypeNode) References() []ua.Reference {
	n.RLock()
	defer n.RUnlock()
	return n.references
}

// SetReferences sets the References of the Variable.
func (n *DataTypeNode) SetReferences(value []ua.Reference) {
	n.Lock()
	defer n.Unlock()
	n.references = value
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *DataTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// DataTypeDefinition returns the DataTypeDefinition attribute of this node.
func (n *DataTypeNode) DataTypeDefinition() any {
	return n.dataTypeDefinition
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *DataTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDIsAbstract, ua.AttributeIDDataTypeDefinition:
		return true
	default:
		return false
	}
}
