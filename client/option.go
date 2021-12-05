// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"crypto/rsa"
	"crypto/tls"

	"github.com/awcullen/opcua"
)

// Option is a functional option to be applied to a client during initialization.
type Option func(*Client) error

// WithSecurityPolicyNone selects endpoint with security policy of None. (default: select most secure endpoint)
func WithSecurityPolicyNone() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURINone
		return nil
	}
}

// WithSecurityPolicyBasic128Rsa15 selects endpoint with security policy of Basic128Rsa15. (default: select most secure endpoint)
func WithSecurityPolicyBasic128Rsa15() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURIBasic128Rsa15
		return nil
	}
}

// WithSecurityPolicyBasic256 selects endpoint with security policy of Basic256. (default: select most secure endpoint)
func WithSecurityPolicyBasic256() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURIBasic256
		return nil
	}
}

// WithSecurityPolicyBasic256Sha256 selects endpoint with security policy of Basic256Sha256. (default: select most secure endpoint)
func WithSecurityPolicyBasic256Sha256() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURIBasic256Sha256
		return nil
	}
}

// WithSecurityPolicyAes128Sha256RsaOaep selects endpoint with security policy of Aes128Sha256RsaOaep. (default: select most secure endpoint)
func WithSecurityPolicyAes128Sha256RsaOaep() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURIAes128Sha256RsaOaep
		return nil
	}
}

// WithSecurityPolicyAes256Sha256RsaPss selects endpoint with security policy of Aes256Sha256RsaPss. (default: select most secure endpoint)
func WithSecurityPolicyAes256Sha256RsaPss() Option {
	return func(c *Client) error {
		c.securityPolicyURI = opcua.SecurityPolicyURIAes256Sha256RsaPss
		return nil
	}
}

// WithUserNameIdentity sets the user identity to a UserNameIdentity created from a username and password. (default: AnonymousIdentity)
func WithUserNameIdentity(userName, password string) Option {
	return func(c *Client) error {
		c.userIdentity = opcua.UserNameIdentity{UserName: userName, Password: password}
		return nil
	}
}

// WithX509Identity sets the user identity to an X509Identity created from a certificate and private key. (default: AnonymousIdentity)
func WithX509Identity(certificate opcua.ByteString, privateKey *rsa.PrivateKey) Option {
	return func(c *Client) error {
		c.userIdentity = opcua.X509Identity{Certificate: certificate, Key: privateKey}
		return nil
	}
}

// WithIssuedIdentity sets the user identity to an IssuedIdentity created from a token. (default: AnonymousIdentity)
func WithIssuedIdentity(tokenData opcua.ByteString) Option {
	return func(c *Client) error {
		c.userIdentity = opcua.IssuedIdentity{TokenData: tokenData}
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

// WithClientCertificateFile sets the file paths of the client certificate and private key.
func WithClientCertificateFile(certPath, keyPath string) Option {
	return func(c *Client) error {
		var err error
		c.applicationCertificate, err = tls.LoadX509KeyPair(certPath, keyPath)
		return err
	}
}

// WithTrustedCertificatesFile sets the file path of the trusted server certificates or certificate authorities.
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
