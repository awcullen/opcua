// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

// MethodNode is a Node class that describes the syntax of a object's Method.
type MethodNode struct {
	sync.RWMutex
	nodeID             opcua.NodeID
	nodeClass          opcua.NodeClass
	browseName         opcua.QualifiedName
	displayName        opcua.LocalizedText
	description        opcua.LocalizedText
	rolePermissions    []opcua.RolePermissionType
	accessRestrictions uint16
	references         []opcua.Reference
	executable         bool
	callMethodHandler  func(context.Context, opcua.CallMethodRequest) opcua.CallMethodResult
}

var _ Node = (*MethodNode)(nil)

// NewMethodNode constructs a new MethodNode.
func NewMethodNode(nodeID opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, executable bool) *MethodNode {
	return &MethodNode{
		nodeID:             nodeID,
		nodeClass:          opcua.NodeClassMethod,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		executable:         executable,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *MethodNode) NodeID() opcua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *MethodNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *MethodNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *MethodNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *MethodNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *MethodNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *MethodNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
	filteredPermissions := []opcua.RolePermissionType{}
	session, ok := ctx.Value(SessionKey).(*Session)
	if !ok {
		return filteredPermissions
	}
	roles := session.UserRoles()
	if len(roles) == 0 {
		return filteredPermissions
	}
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = session.server.rolePermissions
	}
	for _, rp := range rolePermissions {
		for _, r := range roles {
			if rp.RoleID == r {
				filteredPermissions = append(filteredPermissions, rp)
			}
		}
	}
	return filteredPermissions
}

// References returns the References of this node.
func (n *MethodNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *MethodNode) SetReferences(value []opcua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// Executable returns the Executable attribute of this node.
func (n *MethodNode) Executable() bool {
	return n.executable
}

// UserExecutable returns the UserExecutable attribute of this node.
func (n *MethodNode) UserExecutable(ctx context.Context) bool {
	if !n.executable {
		return false
	}
	session, ok := ctx.Value(SessionKey).(*Session)
	if !ok {
		return false
	}
	roles := session.UserRoles()
	rolePermissions := n.RolePermissions()
	if rolePermissions == nil {
		rolePermissions = session.Server().RolePermissions()
	}
	for _, role := range roles {
		for _, rp := range rolePermissions {
			if rp.RoleID == role && rp.Permissions&opcua.PermissionTypeCall != 0 {
				return true
			}
		}
	}
	return false
}

// SetCallMethodHandler sets the CallMethod of the Variable.
func (n *MethodNode) SetCallMethodHandler(value func(context.Context, opcua.CallMethodRequest) opcua.CallMethodResult) {
	n.Lock()
	n.callMethodHandler = value
	n.Unlock()
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *MethodNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDExecutable, opcua.AttributeIDUserExecutable:
		return true
	default:
		return false
	}
}
