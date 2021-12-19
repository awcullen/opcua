// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import "github.com/awcullen/opcua/ua"

// Option is a functional option to be applied to a server during initialization.
type Option func(*Server) error

// WithSessionTimeout sets the number of milliseconds that a session may be unused before being closed by the server. (default: 2 min)
func WithSessionTimeout(value float64) Option {
	return func(srv *Server) error {
		srv.sessionTimeout = value
		return nil
	}
}

// WithMaxSessionCount sets the number of sessions that may be active. (default: no limit)
func WithMaxSessionCount(value uint32) Option {
	return func(srv *Server) error {
		srv.maxSessionCount = value
		return nil
	}
}

// WithMaxSubscriptionCount sets the number of subscription that may be active. (default: no limit)
func WithMaxSubscriptionCount(value uint32) Option {
	return func(srv *Server) error {
		srv.maxSubscriptionCount = value
		return nil
	}
}

// WithServerCapabilities sets the number of subscription that may be active. (default: no limit)
func WithServerCapabilities(value *ua.ServerCapabilities) Option {
	return func(srv *Server) error {
		srv.serverCapabilities = value
		return nil
	}
}

// WithBuildInfo sets the BuildInfo returned by ServerStatus.
func WithBuildInfo(value ua.BuildInfo) Option {
	return func(srv *Server) error {
		srv.buildInfo = value
		return nil
	}
}

// WithInsecureSkipVerify skips verification of client certificate. Skips checking HostName, Expiration, and Authority.
func WithInsecureSkipVerify() Option {
	return func(srv *Server) error {
		srv.suppressCertificateExpired = true
		srv.suppressCertificateChainIncomplete = true
		return nil
	}
}

// WithTransportLimits ...
func WithTransportLimits(receiveBufferSize, sendBufferSize, maxMessageSize, maxChunkCount uint32) Option {
	return func(srv *Server) error {
		srv.receiveBufferSize = receiveBufferSize
		srv.sendBufferSize = sendBufferSize
		srv.maxMessageSize = maxMessageSize
		srv.maxChunkCount = maxChunkCount
		return nil
	}
}

// WithMaxWorkerThreads sets the default number of worker threads that may be created. (default: 4)
func WithMaxWorkerThreads(value int) Option {
	return func(opts *Server) error {
		opts.maxWorkerThreads = value
		return nil
	}
}

// WithServerDiagnostics sets whether to enable the collection of data used for ServerDiagnostics node.
func WithServerDiagnostics(value bool) Option {
	return func(opts *Server) error {
		opts.serverDiagnostics = value
		return nil
	}
}

// WithTrace logs all ServiceRequests and ServiceResponses to StdOut.
func WithTrace() Option {
	return func(srv *Server) error {
		srv.trace = true
		return nil
	}
}

// WithAnonymousIdentity sets whether to allow anonymous identity.
func WithAnonymousIdentity(value bool) Option {
	return func(srv *Server) error {
		srv.allowAnonymousIdentity = value
		return nil
	}
}

// WithSecurityPolicyNone sets whether to allow security policy with no encryption.
func WithSecurityPolicyNone(value bool) Option {
	return func(srv *Server) error {
		srv.allowSecurityPolicyNone = value
		return nil
	}
}

// WithUserNameIdentityAuthenticator sets the authenticator for UserNameIdentity.
func WithUserNameIdentityAuthenticator(authenticator UserNameIdentityAuthenticator) Option {
	return func(srv *Server) error {
		srv.userNameIdentityAuthenticator = authenticator
		return nil
	}
}

// WithAuthenticateUserNameIdentityFunc sets the authenticate func for UserNameIdentity.
func WithAuthenticateUserNameIdentityFunc(f AuthenticateUserNameIdentityFunc) Option {
	return func(srv *Server) error {
		srv.userNameIdentityAuthenticator = f
		return nil
	}
}

// WithX509IdentityAuthenticator sets the authenticator for X509Identity.
func WithX509IdentityAuthenticator(authenticator X509IdentityAuthenticator) Option {
	return func(srv *Server) error {
		srv.x509IdentityAuthenticator = authenticator
		return nil
	}
}

// WithAuthenticateX509IdentityFunc sets the authenticate func for X509Identity.
func WithAuthenticateX509IdentityFunc(f AuthenticateX509IdentityFunc) Option {
	return func(srv *Server) error {
		srv.x509IdentityAuthenticator = f
		return nil
	}
}

// WithRolesProvider sets the RolesProvider.
func WithRolesProvider(provider RolesProvider) Option {
	return func(srv *Server) error {
		srv.rolesProvider = provider
		return nil
	}
}

// WithRolePermissions sets the permissions for each role.
func WithRolePermissions(permissions []ua.RolePermissionType) Option {
	return func(srv *Server) error {
		srv.rolePermissions = permissions
		return nil
	}
}

// WithHistorian sets the HistoryReadWriter.
func WithHistorian(historian HistoryReadWriter) Option {
	return func(srv *Server) error {
		srv.historian = historian
		return nil
	}
}
