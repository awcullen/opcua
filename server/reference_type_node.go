package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua/ua"
)

// ReferenceTypeNode ...
type ReferenceTypeNode struct {
	sync.RWMutex
	nodeID             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	isAbstract         bool
	symmetric          bool
	inverseName        ua.LocalizedText
}

var _ Node = (*ReferenceTypeNode)(nil)

// NewReferenceTypeNode ...
func NewReferenceTypeNode(nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, isAbstract bool, symmetric bool, inverseName ua.LocalizedText) *ReferenceTypeNode {
	return &ReferenceTypeNode{
		nodeID:             nodeID,
		nodeClass:          ua.NodeClassReferenceType,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		isAbstract:         isAbstract,
		symmetric:          symmetric,
		inverseName:        inverseName,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ReferenceTypeNode) NodeID() ua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ReferenceTypeNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ReferenceTypeNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ReferenceTypeNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ReferenceTypeNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ReferenceTypeNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ReferenceTypeNode) UserRolePermissions(ctx context.Context) []ua.RolePermissionType {
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
func (n *ReferenceTypeNode) References() []ua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ReferenceTypeNode) SetReferences(value []ua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// IsAbstract returns the IsAbstract attribute of this node.
func (n *ReferenceTypeNode) IsAbstract() bool {
	return n.isAbstract
}

// Symmetric returns the Symmetric attribute of this node.
func (n *ReferenceTypeNode) Symmetric() bool {
	return n.symmetric
}

// InverseName returns the InverseName attribute of this node.
func (n *ReferenceTypeNode) InverseName() ua.LocalizedText {
	return n.inverseName
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ReferenceTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDIsAbstract, ua.AttributeIDSymmetric,
		ua.AttributeIDInverseName:
		return true
	default:
		return false
	}
}
