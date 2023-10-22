// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"crypto/rsa"
	"crypto/tls"

	"github.com/awcullen/opcua/ua"
)

// Option is a functional option to be applied to a client during initialization.
type Option func(*Client) error

// WithSecurityPolicyURI selects endpoint with given security policy URI and MessageSecurityMode. (default: "" selects most secure endpoint)
func WithSecurityPolicyURI(uri string, securityMode ua.MessageSecurityMode) Option {
	return func(c *Client) error {
		c.securityPolicyURI = uri
		c.securityMode = securityMode
		return nil
	}
}

// WithUserNameIdentity sets the user identity to a UserNameIdentity created from a username and password. (default: AnonymousIdentity)
func WithUserNameIdentity(userName, password string) Option {
	return func(c *Client) error {
		c.userIdentity = ua.UserNameIdentity{UserName: userName, Password: password}
		return nil
	}
}

// WithX509Identity sets the user identity to an X509Identity created from a certificate and private key. (default: AnonymousIdentity)
func WithX509Identity(certificate []byte, privateKey *rsa.PrivateKey) Option {
	return func(c *Client) error {
		c.userIdentity = ua.X509Identity{Certificate: ua.ByteString(certificate), Key: privateKey}
		return nil
	}
}

// WithX509IdentityFile sets the user identity to an X509Identity created from the file paths of the certificate and private key. (default: AnonymousIdentity)
// Reads and parses a public/private key pair from a pair of files. The files must contain PEM encoded data.
// DEPRECIATED. Use WithX509IdentityPaths().
func WithX509IdentityFile(certPath, keyPath string) Option {
	return func(c *Client) error {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		c.userIdentity = ua.X509Identity{Certificate: ua.ByteString(cert.Certificate[0]), Key: cert.PrivateKey.(*rsa.PrivateKey)}
		return nil
	}
}

// WithX509IdentityPaths sets the user identity to an X509Identity created from the file paths of the certificate and private key. (default: AnonymousIdentity)
// Reads and parses a public/private key pair from a pair of files. The files must contain PEM encoded data.
func WithX509IdentityPaths(certPath, keyPath string) Option {
	return func(c *Client) error {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		c.userIdentity = ua.X509Identity{Certificate: ua.ByteString(cert.Certificate[0]), Key: cert.PrivateKey.(*rsa.PrivateKey)}
		return nil
	}
}

// WithIssuedIdentity sets the user identity to an IssuedIdentity created from token data. (default: AnonymousIdentity)
func WithIssuedIdentity(tokenData []byte) Option {
	return func(c *Client) error {
		c.userIdentity = ua.IssuedIdentity{TokenData: ua.ByteString(tokenData)}
		return nil
	}
}

// WithApplicationName sets the name of the client application. (default: package name)
func WithApplicationName(value string) Option {
	return func(c *Client) error {
		c.applicationName = value
		return nil
	}
}

// WithSessionName sets the name of the session. (default: server assigned)
func WithSessionName(value string) Option {
	return func(c *Client) error {
		c.sessionName = value
		return nil
	}
}

// WithSessionTimeout sets the number of milliseconds that a session may be unused before being closed by the server. (default: 2 min)
func WithSessionTimeout(value float64) Option {
	return func(c *Client) error {
		c.sessionTimeout = value
		return nil
	}
}

// WithClientCertificate sets the client certificate and private key.
func WithClientCertificate(cert []byte, privateKey *rsa.PrivateKey) Option {
	return func(c *Client) error {
		var err error
		c.localCertificate, c.localPrivateKey = cert, privateKey
		return err
	}
}

// WithClientCertificateFile sets the file paths of the client certificate and private key.
// Reads and parses a public/private key pair from a pair of files. The files must contain PEM encoded data.
// DEPRECIATED. Use WithClientCertificatePaths().
func WithClientCertificateFile(certPath, keyPath string) Option {
	return func(c *Client) error {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		c.localCertificate = cert.Certificate[0]
		c.localPrivateKey, _ = cert.PrivateKey.(*rsa.PrivateKey)
		return nil
	}
}

// WithClientCertificatePaths sets the paths of the client certificate and private key.
// Reads and parses a public/private key pair from a pair of files. The files must contain PEM encoded data.
func WithClientCertificatePaths(certPath, keyPath string) Option {
	return func(c *Client) error {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		c.localCertificate = cert.Certificate[0]
		c.localPrivateKey, _ = cert.PrivateKey.(*rsa.PrivateKey)
		return nil
	}
}

// WithTrustedCertificatesFile sets the file path of the trusted server certificates or certificate authorities.
// The file must contain PEM encoded data.
// DEPRECIATED. Use WithTrustedCertificatesPath().
func WithTrustedCertificatesFile(path string) Option {
	return func(c *Client) error {
		c.trustedCertsPath = path
		return nil
	}
}

// WithTrustedCertificatesPaths sets the file path of the trusted certificates and revocation lists.
// Path may be to a file, comma-separated list of files, or directory.
func WithTrustedCertificatesPaths(certPath, crlPath string) Option {
	return func(c *Client) error {
		c.trustedCertsPath = certPath
		c.trustedCRLsPath = crlPath
		return nil
	}
}

// WithIssuerCertificatesPath sets the file path of the issuer certificates and revocation lists.
// Issuer certificates are needed for validation, but are not trusted.
// Path may be to a file, comma-separated list of files, or directory.
func WithIssuerCertificatesPaths(certPath, crlPath string) Option {
	return func(c *Client) error {
		c.issuerCertsPath = certPath
		c.issuerCRLsPath = crlPath
		return nil
	}
}

// WithRejectedCertificatesPath sets the file path where rejected certificates are stored.
// Path must be to a directory.
func WithRejectedCertificatesPath(path string) Option {
	return func(c *Client) error {
		c.rejectedCertsPath = path
		return nil
	}
}

// WithInsecureSkipVerify skips verification of server certificate. Skips checking HostName, Expiration, and Authority.
func WithInsecureSkipVerify() Option {
	return func(c *Client) error {
		c.suppressHostNameInvalid = true
		c.suppressCertificateExpired = true
		c.suppressCertificateChainIncomplete = true
		c.suppressCertificateRevocationUnknown = true
		return nil
	}
}

// WithTimeoutHint sets the default number of milliseconds to wait before the ServiceRequest is cancelled. (default: 1500)
func WithTimeoutHint(value uint32) Option {
	return func(c *Client) error {
		c.timeoutHint = value
		return nil
	}
}

// WithDiagnosticsHint sets the default diagnostic hint that is sent in a request. (default: None)
func WithDiagnosticsHint(value uint32) Option {
	return func(c *Client) error {
		c.diagnosticsHint = value
		return nil
	}
}

// WithTokenLifetime sets the requested number of milliseconds before a security token is renewed. (default: 60 min)
func WithTokenLifetime(value uint32) Option {
	return func(c *Client) error {
		c.tokenLifetime = value
		return nil
	}
}

// WithConnectTimeout sets the number of milliseconds to wait for a connection response. (default:5000)
func WithConnectTimeout(value int64) Option {
	return func(c *Client) error {
		c.connectTimeout = value
		return nil
	}
}

// WithTrace logs all ServiceRequests and ServiceResponses to StdOut.
func WithTrace() Option {
	return func(c *Client) error {
		c.trace = true
		return nil
	}
}

// WithTransportLimits sets the limits on the size of the buffers and messages. (default: 64Kb, 64Mb, 4096)
func WithTransportLimits(maxBufferSize, maxMessageSize, maxChunkCount uint32) Option {
	return func(c *Client) error {
		c.maxBufferSize = maxBufferSize
		c.maxMessageSize = maxMessageSize
		c.maxChunkCount = maxChunkCount
		return nil
	}
}
