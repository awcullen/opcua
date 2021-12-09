// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/awcullen/opcua/ua"
)

// validateServerCertificate validates the certificate of the server.
func validateServerCertificate(certificate *x509.Certificate, hostname string, trustedCertsFile string,
	suppressCertificateHostNameInvalid, suppressCertificateTimeInvalid, suppressCertificateChainIncomplete bool) (bool, error) {
	if certificate == nil {
		return false, ua.BadCertificateInvalid
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
				return false, ua.BadCertificateTimeInvalid
			case x509.IncompatibleUsage:
				return false, ua.BadCertificateUseNotAllowed
			default:
				return false, ua.BadSecurityChecksFailed
			}
		case x509.HostnameError:
			return false, ua.BadCertificateHostNameInvalid
		case x509.UnknownAuthorityError:
			return false, ua.BadCertificateChainIncomplete
		default:
			return false, ua.BadSecurityChecksFailed
		}
	}
	return true, nil
}
