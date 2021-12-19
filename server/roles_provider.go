package server

import (
	"crypto/sha1"
	"fmt"

	"github.com/awcullen/opcua/ua"
)

// RolesProvider selects roles where the user identity and connection information matches the membership criteria.
// Roles are identified by a NodeID.  There are a number of well-known roles.
// Later, users are granted Permissions to perform actions based on the user's role memberships.
type RolesProvider interface {
	// GetRoles returns the roles where the user matches the membership criteria.
	GetRoles(userIdentity interface{}, applicationURI string, endpointURL string) ([]ua.NodeID, error)
}

// IdentityMappingRule ...
type IdentityMappingRule struct {
	NodeID              ua.NodeID
	Identities          []ua.IdentityMappingRuleType
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
	DefaultRolePermissions []ua.RolePermissionType = []ua.RolePermissionType{
		{RoleID: ua.ObjectIDWellKnownRoleAnonymous, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead)},
		{RoleID: ua.ObjectIDWellKnownRoleAuthenticatedUser, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead)},
		{RoleID: ua.ObjectIDWellKnownRoleObserver, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeReadHistory | ua.PermissionTypeReceiveEvents)},
		{RoleID: ua.ObjectIDWellKnownRoleOperator, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeReadHistory | ua.PermissionTypeReceiveEvents | ua.PermissionTypeCall)},
		{RoleID: ua.ObjectIDWellKnownRoleEngineer, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeReadHistory | ua.PermissionTypeReceiveEvents | ua.PermissionTypeCall | ua.PermissionTypeWriteHistorizing)},
		{RoleID: ua.ObjectIDWellKnownRoleSupervisor, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeReadHistory | ua.PermissionTypeReceiveEvents | ua.PermissionTypeCall)},
		{RoleID: ua.ObjectIDWellKnownRoleConfigureAdmin, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWriteAttribute)},
		{RoleID: ua.ObjectIDWellKnownRoleSecurityAdmin, Permissions: (ua.PermissionTypeBrowse | ua.PermissionTypeReadRolePermissions | ua.PermissionTypeWriteRolePermissions)},
	}
	// DefaultIdentityMappingRules ...
	DefaultIdentityMappingRules []IdentityMappingRule = []IdentityMappingRule{
		// WellKnownRoleAnonymous
		{
			NodeID: ua.ObjectIDWellKnownRoleAnonymous,
			Identities: []ua.IdentityMappingRuleType{
				{CriteriaType: ua.IdentityCriteriaTypeAnonymous},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleAuthenticatedUser
		{
			NodeID: ua.ObjectIDWellKnownRoleAuthenticatedUser,
			Identities: []ua.IdentityMappingRuleType{
				{CriteriaType: ua.IdentityCriteriaTypeAuthenticatedUser},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleObserver
		{
			NodeID: ua.ObjectIDWellKnownRoleObserver,
			Identities: []ua.IdentityMappingRuleType{
				{CriteriaType: ua.IdentityCriteriaTypeAuthenticatedUser},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleOperator
		{
			NodeID: ua.ObjectIDWellKnownRoleOperator,
			Identities: []ua.IdentityMappingRuleType{
				{CriteriaType: ua.IdentityCriteriaTypeAuthenticatedUser},
			},
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleEngineer
		{
			NodeID:              ua.ObjectIDWellKnownRoleEngineer,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleSupervisor
		{
			NodeID:              ua.ObjectIDWellKnownRoleSupervisor,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleConfigureAdmin
		{
			NodeID:              ua.ObjectIDWellKnownRoleConfigureAdmin,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
		// WellKnownRoleSecurityAdmin
		{
			NodeID:              ua.ObjectIDWellKnownRoleSecurityAdmin,
			ApplicationsExclude: true,
			EndpointsExclude:    true,
		},
	}
)

// IsUserPermitted returns true if the user's role permissions contain a given permissionType.
func IsUserPermitted(userRolePermissions []ua.RolePermissionType, permissionType ua.PermissionType) bool {
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
func (p *RulesBasedRolesProvider) GetRoles(userIdentity interface{}, applicationURI string, endpointURL string) ([]ua.NodeID, error) {
	roles := []ua.NodeID{}
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
			case ua.AnonymousIdentity:
				if identity.CriteriaType == ua.IdentityCriteriaTypeAnonymous {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case ua.UserNameIdentity:
				if identity.CriteriaType == ua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}
				if identity.CriteriaType == ua.IdentityCriteriaTypeUserName && identity.Criteria == id.UserName {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case ua.X509Identity:
				if identity.CriteriaType == ua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}
				thumbprint := fmt.Sprintf("%x", sha1.Sum([]byte(id.Certificate)))
				if identity.CriteriaType == ua.IdentityCriteriaTypeThumbprint && identity.Criteria == thumbprint {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			case ua.IssuedIdentity:
				if identity.CriteriaType == ua.IdentityCriteriaTypeAuthenticatedUser {
					roles = append(roles, rule.NodeID)
					break // continue with next identity
				}

			default:
				return nil, ua.BadUserAccessDenied

			}
		}
	}
	if len(roles) == 0 {
		return nil, ua.BadUserAccessDenied
	}
	return roles, nil
}
