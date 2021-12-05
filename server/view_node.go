package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua"
)

type ViewNode struct {
	sync.RWMutex
	nodeId             opcua.NodeID
	nodeClass          opcua.NodeClass
	browseName         opcua.QualifiedName
	displayName        opcua.LocalizedText
	description        opcua.LocalizedText
	rolePermissions    []opcua.RolePermissionType
	accessRestrictions uint16
	references         []opcua.Reference
	containsNoLoops    bool
	eventNotifier      byte
}

var _ Node = (*ViewNode)(nil)

func NewViewNode(nodeId opcua.NodeID, browseName opcua.QualifiedName, displayName opcua.LocalizedText, description opcua.LocalizedText, rolePermissions []opcua.RolePermissionType, references []opcua.Reference, containsNoLoops bool, eventNotifier byte) *ViewNode {
	return &ViewNode{
		nodeId:             nodeId,
		nodeClass:          opcua.NodeClassView,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		containsNoLoops:    containsNoLoops,
		eventNotifier:      eventNotifier,
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ViewNode) NodeID() opcua.NodeID {
	return n.nodeId
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ViewNode) NodeClass() opcua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ViewNode) BrowseName() opcua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ViewNode) DisplayName() opcua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ViewNode) Description() opcua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ViewNode) RolePermissions() []opcua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ViewNode) UserRolePermissions(ctx context.Context) []opcua.RolePermissionType {
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
func (n *ViewNode) References() []opcua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ViewNode) SetReferences(value []opcua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// ContainsNoLoops returns the ContainsNoLoops attribute of this node.
func (n *ViewNode) ContainsNoLoops() bool {
	return n.containsNoLoops
}

// EventNotifier returns the EventNotifier attribute of this node.
func (n *ViewNode) EventNotifier() byte {
	return n.eventNotifier
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ViewNode) IsAttributeIDValid(attributeId uint32) bool {
	switch attributeId {
	case opcua.AttributeIDNodeID, opcua.AttributeIDNodeClass, opcua.AttributeIDBrowseName,
		opcua.AttributeIDDisplayName, opcua.AttributeIDDescription, opcua.AttributeIDRolePermissions,
		opcua.AttributeIDUserRolePermissions, opcua.AttributeIDContainsNoLoops, opcua.AttributeIDEventNotifier:
		return true
	default:
		return false
	}
}
