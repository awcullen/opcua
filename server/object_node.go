// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"sync"

	"github.com/awcullen/opcua/ua"
)

// ObjectNode ...
type ObjectNode struct {
	sync.RWMutex
	nodeID             ua.NodeID
	nodeClass          ua.NodeClass
	browseName         ua.QualifiedName
	displayName        ua.LocalizedText
	description        ua.LocalizedText
	rolePermissions    []ua.RolePermissionType
	accessRestrictions uint16
	references         []ua.Reference
	eventNotifier      byte
	subs               map[EventListener]struct{}
}

var _ Node = (*ObjectNode)(nil)

// NewObjectNode ...
func NewObjectNode(nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, rolePermissions []ua.RolePermissionType, references []ua.Reference, eventNotifier byte) *ObjectNode {
	return &ObjectNode{
		nodeID:             nodeID,
		nodeClass:          ua.NodeClassObject,
		browseName:         browseName,
		displayName:        displayName,
		description:        description,
		rolePermissions:    rolePermissions,
		accessRestrictions: 0,
		references:         references,
		eventNotifier:      eventNotifier,
		subs:               map[EventListener]struct{}{},
	}
}

// NodeID returns the NodeID attribute of this node.
func (n *ObjectNode) NodeID() ua.NodeID {
	return n.nodeID
}

// NodeClass returns the NodeClass attribute of this node.
func (n *ObjectNode) NodeClass() ua.NodeClass {
	return n.nodeClass
}

// BrowseName returns the BrowseName attribute of this node.
func (n *ObjectNode) BrowseName() ua.QualifiedName {
	return n.browseName
}

// DisplayName returns the DisplayName attribute of this node.
func (n *ObjectNode) DisplayName() ua.LocalizedText {
	return n.displayName
}

// Description returns the Description attribute of this node.
func (n *ObjectNode) Description() ua.LocalizedText {
	return n.description
}

// RolePermissions returns the RolePermissions attribute of this node.
func (n *ObjectNode) RolePermissions() []ua.RolePermissionType {
	return n.rolePermissions
}

// UserRolePermissions returns the RolePermissions attribute of this node for the current user.
func (n *ObjectNode) UserRolePermissions(ctx context.Context) []ua.RolePermissionType {
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
func (n *ObjectNode) References() []ua.Reference {
	n.RLock()
	res := n.references
	n.RUnlock()
	return res
}

// SetReferences sets the References of the Variable.
func (n *ObjectNode) SetReferences(value []ua.Reference) {
	n.Lock()
	n.references = value
	n.Unlock()
}

// EventNotifier returns the EventNotifier attribute of this node.
func (n *ObjectNode) EventNotifier() byte {
	return n.eventNotifier
}

// OnEvent raises an event from this node.
func (n *ObjectNode) OnEvent(evt ua.Event) {
	n.RLock()
	defer n.RUnlock()
	for sub := range n.subs {
		sub.OnEvent(evt)
	}
}

type EventListener interface {
	OnEvent(ua.Event)
}

func (n *ObjectNode) AddEventListener(listener EventListener) {
	n.Lock()
	n.subs[listener] = struct{}{}
	n.Unlock()
}

func (n *ObjectNode) RemoveEventListener(listener EventListener) {
	n.Lock()
	delete(n.subs, listener)
	n.Unlock()
}

// IsAttributeIDValid returns true if attributeId is supported for the node.
func (n *ObjectNode) IsAttributeIDValid(attributeID uint32) bool {
	switch attributeID {
	case ua.AttributeIDNodeID, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName, ua.AttributeIDDescription, ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions, ua.AttributeIDEventNotifier:
		return true
	default:
		return false
	}
}
