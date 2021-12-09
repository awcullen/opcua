package server

import "github.com/awcullen/opcua/ua"

// UserNameIdentityAuthenticator authenticates UserNameIdentity.
type UserNameIdentityAuthenticator interface {
	// AuthenticateUserNameIdentity returns nil when user identity is authenticated, or BadUserAccessDenied otherwise.
	AuthenticateUserNameIdentity(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error
}

// AuthenticateUserNameIdentityFunc authenticates UserNameIdentity.
type AuthenticateUserNameIdentityFunc func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error

// AuthenticateUserNameIdentity ...
func (f AuthenticateUserNameIdentityFunc) AuthenticateUserNameIdentity(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}

// X509IdentityAuthenticator authenticates X509Identity.
type X509IdentityAuthenticator interface {
	// AuthenticateUser returns nil when user is authenticated, or BadUserAccessDenied otherwise.
	AuthenticateX509Identity(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error
}

// AuthenticateX509IdentityFunc authenticates X509Identity.
type AuthenticateX509IdentityFunc func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error

// AuthenticateX509Identity ...
func (f AuthenticateX509IdentityFunc) AuthenticateX509Identity(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}

// IssuedIdentityAuthenticator authenticates user identities.
type IssuedIdentityAuthenticator interface {
	// AuthenticateIssuedIdentity returns nil when user is authenticated, or BadUserAccessDenied otherwise.
	AuthenticateIssuedIdentity(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error
}

// AuthenticateIssuedIdentityFunc authenticates user identities.
type AuthenticateIssuedIdentityFunc func(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error

// AuthenticateIssuedIdentity ...
func (f AuthenticateIssuedIdentityFunc) AuthenticateIssuedIdentity(userIdentity ua.IssuedIdentity, applicationURI string, endpointURL string) error {
	return f(userIdentity, applicationURI, endpointURL)
}
