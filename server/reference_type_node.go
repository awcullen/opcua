package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

// ReferenceTypeNode ...
type ReferenceTypeNode struct {
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
	symmetric          bool
	inverseName        opcua.LocalizedText
}

var _ Node = (*ReferenceTypeNode)(nil)

// NewReferenceTypeNode ...
func NewReferenceTypeNode(nodeID opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, isAbstract bool, symmetric bool, inverseName opcua.LocalizedText) *ReferenceTypeNode {
	return &ReferenceTypeNode{
		nodeID:             nodeID,
		nodeClass:          opcua.NodeClassReferenceType,
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
func (n *ReferenceTypeNode) NodeID() opcua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ReferenceTypeNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ReferenceTypeNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ReferenceTypeNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ReferenceTypeNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ReferenceTypeNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ReferenceTypeNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
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
func (n *ReferenceTypeNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ReferenceTypeNode) SetReferences(value []opcua.Reference) {
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
func (n *ReferenceTypeNode) InverseName() opcua.LocalizedText {
	return n.inverseName
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ReferenceTypeNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDIsAbstract, opcua.AttributeIDSymmetric,
		opcua.AttributeIDInverseName:
		return true
	default:
		return false
	}
}
