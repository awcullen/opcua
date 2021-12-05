// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

// ObjectTypeNode ...
type ObjectTypeNode struct {
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
}

var _ Node = (*ObjectTypeNode)(nil)

// NewObjectTypeNode ...
func NewObjectTypeNode(nodeID opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, isAbstract bool) *ObjectTypeNode {
	return &ObjectTypeNode{
		nodeID:             nodeID,
		nodeClass:          opcua.NodeClassObjectType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		isAbstract:         isAbstract,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ObjectTypeNode) NodeID() opcua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ObjectTypeNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ObjectTypeNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ObjectTypeNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ObjectTypeNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ObjectTypeNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ObjectTypeNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
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
func (n *ObjectTypeNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ObjectTypeNode) SetReferences(value []opcua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *ObjectTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ObjectTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDIsAbstract:
		return true
	default:
		return false
	}
}
