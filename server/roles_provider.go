package server

import (
	"crypto/sha1"
	"fmt"

	"github.com/awcullen/opcua"
)

// RolesProvider selects roles where the user identity and connection information matches the membership criteria.
// Roles are identified by a NodeID.  There are a number of well-known roles.
// Later, users are granted Permissions to perform actions based on the user's role memberships.
type RolesProvider interface {
	// GetRoles returns the roles where the user matches the membership criteria.
	GetRoles(userIdentity interface{}, applicationURI string, endpointURL string) ([]opcua.NodeID, error)
}

// IdentityMappingRule ...
type IdentityMappingRule struct {
	NodeID              opcua.NodeID
	Identities          []opcua.IdentityMappingRuleType
	ApplicationsExclude bool
	Applications        []string
	EndpointsExclude    bool
	Endpoints           []struct {
		EndpointUrl         string
		SecurityMode        string
		SecurityPolicyURI   string
		TransportProfileUri string
	}
}

var (
	// DefaultRolePermissions returns RolePermissionTypes for the well known roles.
	DefaultRolePermissions []opcua.RolePermissionType = []opcua.RolePermissionType{
		{RoleID: opcua.ObjectIDWellKnownRoleAnonymous, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead)},
		{RoleID: opcua.ObjectIDWellKnownRoleAuthenticatedUser, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead)},
		{RoleID: opcua.ObjectIDWellKnownRoleObserver, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead | opcua.PermissionTypeReadHistory | opcua.PermissionTypeReceiveEvents)},
		{RoleID: opcua.ObjectIDWellKnownRoleOperator, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead | opcua.PermissionTypeWrite | opcua.PermissionTypeReadHistory | opcua.PermissionTypeReceiveEvents | opcua.PermissionTypeCall)},
		{RoleID: opcua.ObjectIDWellKnownRoleEngineer, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead | opcua.PermissionTypeWrite | opcua.PermissionTypeReadHistory | opcua.PermissionTypeReceiveEvents | opcua.PermissionTypeCall | opcua.PermissionTypeWriteHistorizing)},
		{RoleID: opcua.ObjectIDWellKnownRoleSupervisor, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead | opcua.PermissionTypeWrite | opcua.PermissionTypeReadHistory | opcua.PermissionTypeReceiveEvents | opcua.PermissionTypeCall)},
		{RoleID: opcua.ObjectIDWellKnownRoleConfigureAdmin, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeRead | opcua.PermissionTypeWriteAttribute)},
		{RoleID: opcua.ObjectIDWellKnownRoleSecurityAdmin, Permissions: (opcua.PermissionTypeBrowse | opcua.PermissionTypeReadRolePermissions | opcua.PermissionTypeWriteRolePermissions)},
	}
	// DefaultIdentityMappingRules ...
	DefaultIdentityMappingRules []IdentityMappingRule = []IdentityMappingRule{
		// WellKnownRoleAnonymous
		{
			NodeID: opcua.ObjectIDWellKnownRoleAnonymous,
			Identities: []opcua.IdentityMappingRuleType{
				{CriteriaType: opcua.IdentityCriteriaTypeAnonymous},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleAuthenticatedUser
		{
			NodeID: opcua.ObjectIDWellKnownRoleAuthenticatedUser,
			Identities: []opcua.IdentityMappingRuleType{
				{CriteriaType: opcua.IdentityCriteriaTypeAuthenticatedUser},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleObserver
		{
			NodeID:              opcua.ObjectIDWellKnownRoleObserver,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleOperator
		{
			NodeID:              opcua.ObjectIDWellKnownRoleOperator,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleEngineer
		{
			NodeID:              opcua.ObjectIDWellKnownRoleEngineer,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleSupervisor
		{
			NodeID:              opcua.ObjectIDWellKnownRoleSupervisor,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleConfigureAdmin
		{
			NodeID:              opcua.ObjectIDWellKnownRoleConfigureAdmin,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleSecurityAdmin
		{
			NodeID:              opcua.ObjectIDWellKnownRoleSecurityAdmin,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
	}
)

// IsUserPermitted returns true if the user's role permissions contain a given permissionType.
func IsUserPermitted(userRolePermissions []opcua.RolePermissionType, permissionType opcua.PermissionType) bool {
	for _, rp := range userRolePermissions {
		if rp.Permissions&permissionType != 0 {
			return true
		}
	}
	return false
}

// RulesBasedRolesProvider returns WellKnownRoles given server identity mapping rules.
type RulesBasedRolesProvider struct {
	identityMappingRules []IdentityMappingRule
}

// NewRulesBasedRolesProvider ...
func NewRulesBasedRolesProvider(rules []IdentityMappingRule) RolesProvider {
	return &RulesBasedRolesProvider{
		identityMappingRules: rules,
	}
}

// GetRoles ...
func (p *RulesBasedRolesProvider) GetRoles(userIdentity interface{}, applicationURI string, endpointURL string) ([]opcua.NodeID, error) {
	roles := []opcua.NodeID{}
	for _, rule := range p.identityMappingRules {
		ok := rule.ApplicationsExclude // true means the following applications should be excluded
		for _, uri := range rule.Applications {
			if uri == applicationURI {
				ok = !rule.ApplicationsExclude
				break
			}
		}
		if !ok {
			break // continue with next rule
		}
		ok = rule.EndpointsExclude // true means the following endpoints should be excluded
		for _, ep := range rule.Endpoints {
			if ep.EndpointUrl == endpointURL {
				ok = !rule.EndpointsExclude
				break
			}
		}
		if !ok {
			break // continue with next role
		}
		for _, identity := range rule.Identities {

			switch id := userIdentity.(type) {
			case opcua.AnonymousIdentity:
				if identity.CriteriaType == opcua.IdentityCriteriaTypeAnonymous {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case opcua.UserNameIdentity:
				if identity.CriteriaType == opcua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}
				if identity.CriteriaType == opcua.IdentityCriteriaTypeUserName && identity.Criteria == id.UserName {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case opcua.X509Identity:
				if identity.CriteriaType == opcua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}
				thumbprint := fmt.Sprintf("%x", sha1.Sum([]byte(id.Certificate)))
				if identity.CriteriaType == opcua.IdentityCriteriaTypeThumbprint && identity.Criteria == thumbprint {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case opcua.IssuedIdentity:
				if identity.CriteriaType == opcua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			default:
				return nil, opcua.BadUserAccessDenied

			}
		}
	}
	if len(roles) == 0 {
		return nil, opcua.BadUserAccessDenied
	}
	return roles, nil
}
