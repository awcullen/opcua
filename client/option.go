// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"crypto/rsa"
	"crypto/tls"

	"github.com/awcullen/opcua/ua"
)

// Option is a functional option to be applied to a client during initialization.
type Option func(*Client) error

// WithSecurityPolicyURI selects endpoint with given security policy URI. (default: "" selects most secure endpoint)
func WithSecurityPolicyURI(uri string) Option {
	return func(c *Client) error {
		c.securityPolicyURI = uri
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
func WithX509Identity(certificate ua.ByteString, privateKey *rsa.PrivateKey) Option {
	return func(c *Client) error {
		c.userIdentity = ua.X509Identity{Certificate: certificate, Key: privateKey}
		return nil
	}
}

// WithIssuedIdentity sets the user identity to an IssuedIdentity created from a token. (default: AnonymousIdentity)
func WithIssuedIdentity(tokenData ua.ByteString) Option {
	return func(c *Client) error {
		c.userIdentity = ua.IssuedIdentity{TokenData: tokenData}
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

// WithTrustedCertificatesFile sets the file path of the trusted server certificates or certificate authorities.
// The files must contain PEM encoded data.
func WithTrustedCertificatesFile(path string) Option {
	return func(c *Client) error {
		c.trustedCertsFile = path
		return nil
	}
}

// WithInsecureSkipVerify skips verification of server certificate. Skips checking HostName, Expiration, and Authority.
func WithInsecureSkipVerify() Option {
	return func(c *Client) error {
		c.suppressHostNameInvalid = true
		c.suppressCertificateExpired = true
		c.suppressCertificateChainIncomplete = true
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
