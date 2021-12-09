package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua/ua"
)

type ViewNode struct {
	sync.RWMutex
	nodeId             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	containsNoLoops    bool
	eventNotifier      byte
}

var _ Node = (*ViewNode)(nil)

func NewViewNode(nodeId ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, containsNoLoops bool, eventNotifier byte) *ViewNode {
	return &ViewNode{
		nodeId:             nodeId,
		nodeClass:          ua.NodeClassView,
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
func (n *ViewNode) NodeID() ua.NodeID {
	return n.nodeId
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ViewNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ViewNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ViewNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ViewNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ViewNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ViewNode) UserRolePermissions(ctx context.Context) []ua.RolePermissionType {
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
func (n *ViewNode) References() []ua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ViewNode) SetReferences(value []ua.Reference) {
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
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDContainsNoLoops, ua.AttributeIDEventNotifier:
		return true
	default:
		return false
	}
}
