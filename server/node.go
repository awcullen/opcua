// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"

	"github.com/awcullen/opcua"
)

// Node ...
type Node interface {
	NodeID() opcua.NodeID
	NodeClass() opcua.NodeClass
	BrowseName() opcua.QualifiedName
	DisplayName() opcua.LocalizedText
	Description() opcua.LocalizedText
	RolePermissions() []opcua.RolePermissionType
	UserRolePermissions(context.Context) []opcua.RolePermissionType
	References() []opcua.Reference
	SetReferences([]opcua.Reference)
	IsAttributeIDValid(uint32) bool
}
