// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

// ObjectNode ...
type ObjectNode struct {
	sync.RWMutex
	nodeID             opcua.NodeID
	nodeClass          opcua.NodeClass
	browseName         opcua.QualifiedName
	displayName        opcua.LocalizedText
	description        opcua.LocalizedText
	rolePermissions    []opcua.RolePermissionType
	accessRestrictions uint16
	references         []opcua.Reference
	eventNotifier      byte
}

var _ Node = (*ObjectNode)(nil)

// NewObjectNode ...
func NewObjectNode(nodeID opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, eventNotifier byte) *ObjectNode {
	return &ObjectNode{
		nodeID:             nodeID,
		nodeClass:          opcua.NodeClassObject,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		eventNotifier:      eventNotifier,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ObjectNode) NodeID() opcua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ObjectNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ObjectNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ObjectNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ObjectNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ObjectNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ObjectNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
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
func (n *ObjectNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ObjectNode) SetReferences(value []opcua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// EventNotifier returns the EventNotifier attribute of this node.
func (n *ObjectNode) EventNotifier() byte {
	return n.eventNotifier
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ObjectNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDEventNotifier:
		return true
	default:
		return false
	}
}
