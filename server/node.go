// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"github.com/awcullen/opcua/ua"
)

// Node ...
type Node interface {
	NodeID() ua.NodeID
	NodeClass() ua.NodeClass
	BrowseName() ua.QualifiedName
	DisplayName() ua.LocalizedText
	Description() ua.LocalizedText
	RolePermissions() []ua.RolePermissionType
	UserRolePermissions(userIdentity any) []ua.RolePermissionType
	References() []ua.Reference
	SetReferences([]ua.Reference)
	IsAttributeIDValid(uint32) bool
}
