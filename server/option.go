// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"net/url"

	"github.com/awcullen/opcua/ua"
)

// Option is a functional option to be applied to a server during initialization.
type Option func(*Server) error

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

// WithServerCapabilities sets the ServerCapabilities.
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

// WithTrustedCertificatesPaths sets the file path of the trusted certificates and revocation lists.
// Path may be to a file, comma-separated list of files, or directory.
func WithTrustedCertificatesPaths(certPath, crlPath string) Option {
	return func(srv *Server) error {
		srv.trustedCertsPath = certPath
		srv.trustedCRLsPath = crlPath
		return nil
	}
}

// WithIssuerCertificatesPaths sets the file path of the issuer certificates and revocation lists.
// Issuer certificates are needed for validation, but are not trusted.
// Path may be to a file, comma-separated list of files, or directory.
func WithIssuerCertificatesPaths(certPath, crlPath string) Option {
	return func(srv *Server) error {
		srv.issuerCertsPath = certPath
		srv.issuerCRLsPath = crlPath
		return nil
	}
}

// WithRejectedCertificatesPath sets the file path where rejected certificates are stored.
// Path must be to a directory.
func WithRejectedCertificatesPath(path string) Option {
	return func(srv *Server) error {
		srv.rejectedCertsPath = path
		return nil
	}
}

// WithInsecureSkipVerify skips verification of client certificate. Skips checking HostName, Expiration, and Authority.
func WithInsecureSkipVerify() Option {
	return func(srv *Server) error {
		srv.suppressCertificateExpired = true
		srv.suppressCertificateChainIncomplete = true
		srv.suppressCertificateRevocationUnknown = true
		return nil
	}
}

// WithTransportLimits sets the limits on the size of the buffers and messages. (default: 64Kb, 64Mb, 4096)
func WithTransportLimits(maxBufferSize, maxMessageSize, maxChunkCount uint32) Option {
	return func(srv *Server) error {
		srv.maxBufferSize = maxBufferSize
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
		if value {
			srv.anonymousIdentityAuthenticator = AuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
				return nil
			})
		} else {
			srv.anonymousIdentityAuthenticator = nil
		}
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

// WithAnonymousIdentityAuthenticator sets the authenticator for AnonymousIdentity.
// Provided authenticator can check applicationURI of the client certificate, if provided.
func WithAnonymousIdentityAuthenticator(authenticator AnonymousIdentityAuthenticator) Option {
	return func(srv *Server) error {
		srv.anonymousIdentityAuthenticator = authenticator
		return nil
	}
}

// WithAuthenticateAnonymousIdentityFunc sets the authenticate func for AnonymousIdentity.
// Provided function can check applicationURI of the client certificate, if provided.
func WithAuthenticateAnonymousIdentityFunc(f AuthenticateAnonymousIdentityFunc) Option {
	return func(srv *Server) error {
		srv.anonymousIdentityAuthenticator = f
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

// WithGetRolesFunc sets the GetRolesFunc that returns the roles for the given user identity.
func WithGetRolesFunc(f GetRolesFunc) Option {
	return func(srv *Server) error {
		srv.rolesProvider = f
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

// WithReverseConnect sets the URLs of clients the server connects to, in addition to
// listening for incoming connections. For each URL, the server opens a socket to the
// client, sends a ReverseHello message and then waits for the client to open a secure
// channel on that socket, as defined in https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.3
// The server holds one socket per client at a time and opens the next one after it
// closes, waiting a short delay after a socket that ended well and a delay that doubles
// (up to 30s) after a failure: a failed dial, or a peer that sent bytes that did not open
// a secure channel. Each URL has the form
// opc.tcp://[host]:[port]
func WithReverseConnect(clientURLs ...string) Option {
	return func(srv *Server) error {
		for _, clientURL := range clientURLs {
			u, err := url.Parse(clientURL)
			if err != nil || u.Scheme != "opc.tcp" || u.Hostname() == "" || u.Port() == "" {
				return ua.BadTCPEndpointURLInvalid
			}
		}
		srv.reverseConnectURLs = append(srv.reverseConnectURLs, clientURLs...)
		return nil
	}
}

// WithReverseConnectStateFunc sets a function the server calls with the state of each
// reverse connection: a nil error when the client opened a secure channel on a reverse
// socket, or the error that ended an attempt (a failed dial, a failed ReverseHello, or a
// peer that sent bytes that did not open a secure channel). A socket the client closed or
// let time out without sending anything is not reported. It is called from the goroutine
// that serves the client and must not block.
func WithReverseConnectStateFunc(f func(clientURL string, err error)) Option {
	return func(srv *Server) error {
		srv.reverseConnectStateFunc = f
		return nil
	}
}
