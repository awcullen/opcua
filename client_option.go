// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"crypto/rsa"
	"crypto/tls"
)

// ClientOption is a functional option to be applied to a client during initialization.
type ClientOption func(*clientOptions) error

// WithSecurityPolicyNone selects endpoint with security policy of None. (default: select most secure endpoint)
func WithSecurityPolicyNone() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURINone
		return nil
	}
}

// WithSecurityPolicyBasic128Rsa15 selects endpoint with security policy of Basic128Rsa15. (default: select most secure endpoint)
func WithSecurityPolicyBasic128Rsa15() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURIBasic128Rsa15
		return nil
	}
}

// WithSecurityPolicyBasic256 selects endpoint with security policy of Basic256. (default: select most secure endpoint)
func WithSecurityPolicyBasic256() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURIBasic256
		return nil
	}
}

// WithSecurityPolicyBasic256Sha256 selects endpoint with security policy of Basic256Sha256. (default: select most secure endpoint)
func WithSecurityPolicyBasic256Sha256() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURIBasic256Sha256
		return nil
	}
}

// WithSecurityPolicyAes128Sha256RsaOaep selects endpoint with security policy of Aes128Sha256RsaOaep. (default: select most secure endpoint)
func WithSecurityPolicyAes128Sha256RsaOaep() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURIAes128Sha256RsaOaep
		return nil
	}
}

// WithSecurityPolicyAes256Sha256RsaPss selects endpoint with security policy of Aes256Sha256RsaPss. (default: select most secure endpoint)
func WithSecurityPolicyAes256Sha256RsaPss() ClientOption {
	return func(opts *clientOptions) error {
		opts.SecurityPolicyURI = SecurityPolicyURIAes256Sha256RsaPss
		return nil
	}
}

// WithUserNameIdentity sets the user identity to a UserNameIdentity created from a username and password. (default: AnonymousIdentity)
func WithUserNameIdentity(userName, password string) ClientOption {
	return func(opts *clientOptions) error {
		opts.UserIdentity = &UserNameIdentity{UserName: userName, Password: password}
		return nil
	}
}

// WithX509Identity sets the user identity to an X509Identity created from a certificate and private key. (default: AnonymousIdentity)
func WithX509Identity(certificate ByteString, privateKey *rsa.PrivateKey) ClientOption {
	return func(opts *clientOptions) error {
		opts.UserIdentity = &X509Identity{Certificate: certificate, Key: privateKey}
		return nil
	}
}

// WithIssuedIdentity sets the user identity to an IssuedIdentity created from a token. (default: AnonymousIdentity)
func WithIssuedIdentity(tokenData ByteString) ClientOption {
	return func(opts *clientOptions) error {
		opts.UserIdentity = &IssuedIdentity{TokenData: tokenData}
		return nil
	}
}

// WithApplicationName sets the name of the client application. (default: package name)
func WithApplicationName(value string) ClientOption {
	return func(opts *clientOptions) error {
		opts.ApplicationName = value
		return nil
	}
}

// WithSessionName sets the name of the session. (default: server assigned)
func WithSessionName(value string) ClientOption {
	return func(opts *clientOptions) error {
		opts.SessionName = value
		return nil
	}
}

// WithSessionTimeout sets the number of milliseconds that a session may be unused before being closed by the server. (default: 2 min)
func WithSessionTimeout(value float64) ClientOption {
	return func(opts *clientOptions) error {
		opts.SessionTimeout = value
		return nil
	}
}

// WithClientCertificateFile sets the file paths of the client certificate and private key.
func WithClientCertificateFile(certPath, keyPath string) ClientOption {
	return func(opts *clientOptions) error {
		var err error
		opts.ApplicationCertificate, err = tls.LoadX509KeyPair(certPath, keyPath)
		// opts.CertFile = certPath
		// opts.KeyFile = keyPath
		return err
	}
}

// WithTrustedCertificatesFile sets the file path of the trusted server certificates or certificate authorities.
func WithTrustedCertificatesFile(path string) ClientOption {
	return func(opts *clientOptions) error {
		opts.TrustedCertsFile = path
		return nil
	}
}

// WithInsecureSkipVerify skips verification of server certificate. Skips checking HostName, Expiration, and Authority.
func WithInsecureSkipVerify() ClientOption {
	return func(opts *clientOptions) error {
		opts.SuppressHostNameInvalid = true
		opts.SuppressCertificateExpired = true
		opts.SuppressCertificateChainIncomplete = true
		return nil
	}
}

// WithTimeoutHint sets the default number of milliseconds to wait before the ServiceRequest is cancelled. (default: 1500)
func WithTimeoutHint(value uint32) ClientOption {
	return func(opts *clientOptions) error {
		opts.TimeoutHint = value
		return nil
	}
}

// WithDiagnosticsHint sets the default diagnostic hint that is sent in a request. (default: None)
func WithDiagnosticsHint(value uint32) ClientOption {
	return func(opts *clientOptions) error {
		opts.DiagnosticsHint = value
		return nil
	}
}

// WithTokenLifetime sets the requested number of milliseconds before a security token is renewed. (default: 60 min)
func WithTokenLifetime(value uint32) ClientOption {
	return func(opts *clientOptions) error {
		opts.TokenLifetime = value
		return nil
	}
}

// WithConnectTimeout sets the number of milliseconds to wait for a connection response. (default:5000)
func WithConnectTimeout(value int64) ClientOption {
	return func(opts *clientOptions) error {
		opts.ConnectTimeout = value
		return nil
	}
}

// WithTrace logs all ServiceRequests and ServiceResponses to StdOut.
func WithTrace() ClientOption {
	return func(opts *clientOptions) error {
		opts.Trace = true
		return nil
	}
}
