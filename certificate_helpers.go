// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"strings"
)

// GetCertificateFromFile reads the certificate and private key from files.
func GetCertificateFromFile(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var crt *x509.Certificate
	var key *rsa.PrivateKey

	buf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, BadCertificateInvalid
	}
	for len(buf) > 0 {
		var block *pem.Block
		block, buf = pem.Decode(buf)
		if block == nil {
			// maybe its ASN.1 DER data
			cert, err := x509.ParseCertificate(buf)
			if err == nil {
				crt = cert
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			crt = cert
		}
		break
	}
	if crt == nil {
		return nil, nil, BadCertificateInvalid
	}

	buf, err = ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, BadCertificateInvalid
	}
	if block, _ := pem.Decode(buf); block != nil && (strings.HasSuffix(block.Type, "PRIVATE KEY")) {
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			key = k
		} else {
			if k2, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if k3, ok := k2.(*rsa.PrivateKey); ok {
					key = k3
				}
			}
		}
	}
	if key == nil {
		return nil, nil, BadCertificateInvalid
	}
	return crt, key, nil
}

// ValidateServerCertificate validates the certificate of the server.
func ValidateServerCertificate(certificate *x509.Certificate, hostname string, trustedCertsFile string,
	suppressCertificateHostNameInvalid, suppressCertificateTimeInvalid, suppressCertificateChainIncomplete bool) (bool, error) {
	if certificate == nil {
		return false, BadCertificateInvalid
	}
	var intermediates, roots *x509.CertPool
	if buf, err := ioutil.ReadFile(trustedCertsFile); err == nil {
		for len(buf) > 0 {
			var block *pem.Block
			block, buf = pem.Decode(buf)
			if block == nil {
				// maybe its der
				cert, err := x509.ParseCertificate(buf)
				if err == nil {
					// is self-signed?
					if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
						if roots == nil {
							roots = x509.NewCertPool()
						}
						roots.AddCert(cert)
					} else {
						if intermediates == nil {
							intermediates = x509.NewCertPool()
						}
						intermediates.AddCert(cert)
					}
				}
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			// is self-signed?
			if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				if roots == nil {
					roots = x509.NewCertPool()
				}
				roots.AddCert(cert)
			} else {
				if intermediates == nil {
					intermediates = x509.NewCertPool()
				}
				intermediates.AddCert(cert)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:       hostname,
	}

	if suppressCertificateHostNameInvalid {
		opts.DNSName = ""
	}

	if suppressCertificateTimeInvalid {
		opts.CurrentTime = certificate.NotBefore
	}

	if suppressCertificateChainIncomplete {
		if opts.Roots == nil {
			opts.Roots = x509.NewCertPool()
		}
		opts.Roots.AddCert(certificate)
	}

	// build chain and verify
	if _, err := certificate.Verify(opts); err != nil {
		switch se := err.(type) {
		case x509.CertificateInvalidError:
			switch se.Reason {
			case x509.Expired:
				return false, BadCertificateTimeInvalid
			case x509.IncompatibleUsage:
				return false, BadCertificateUseNotAllowed
			default:
				return false, BadSecurityChecksFailed
			}
		case x509.HostnameError:
			return false, BadCertificateHostNameInvalid
		case x509.UnknownAuthorityError:
			return false, BadCertificateChainIncomplete
		default:
			return false, BadSecurityChecksFailed
		}
	}
	return true, nil
}

// ValidateClientCertificate validates the certificate of the client.
func ValidateClientCertificate(certificate *x509.Certificate, trustedCertsFile string,
	suppressCertificateTimeInvalid, suppressCertificateChainIncomplete bool) (bool, error) {
	if certificate == nil {
		return false, BadCertificateInvalid
	}
	var intermediates, roots *x509.CertPool
	if buf, err := ioutil.ReadFile(trustedCertsFile); err == nil {
		for len(buf) > 0 {
			var block *pem.Block
			block, buf = pem.Decode(buf)
			if block == nil {
				// maybe its der
				cert, err := x509.ParseCertificate(buf)
				if err == nil {
					// is self-signed?
					if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
						if roots == nil {
							roots = x509.NewCertPool()
						}
						roots.AddCert(cert)
					} else {
						if intermediates == nil {
							intermediates = x509.NewCertPool()
						}
						intermediates.AddCert(cert)
					}
				}
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			// is self-signed?
			if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				if roots == nil {
					roots = x509.NewCertPool()
				}
				roots.AddCert(cert)
			} else {
				if intermediates == nil {
					intermediates = x509.NewCertPool()
				}
				intermediates.AddCert(cert)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if suppressCertificateTimeInvalid {
		opts.CurrentTime = certificate.NotAfter // causes test to pass
	}

	if suppressCertificateChainIncomplete {
		if opts.Roots == nil {
			opts.Roots = x509.NewCertPool()
		}
		opts.Roots.AddCert(certificate)
	}

	// build chain and verify
	if _, err := certificate.Verify(opts); err != nil {
		switch se := err.(type) {
		case x509.CertificateInvalidError:
			switch se.Reason {
			case x509.Expired:
				return false, BadCertificateTimeInvalid
			case x509.IncompatibleUsage:
				return false, BadCertificateUseNotAllowed
			default:
				return false, BadSecurityChecksFailed
			}
		case x509.UnknownAuthorityError:
			return false, BadSecurityChecksFailed
		default:
			return false, BadSecurityChecksFailed
		}
	}
	return true, nil
}
