package ua

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ValidateCertificate validates the certificate.
func ValidateCertificate(certificate *x509.Certificate, keyUsages []x509.ExtKeyUsage, hostname, trustedPath, trustedCRLPath, issuersPath, issuersCRLPath, rejectedCertsPath string,
	suppressCertificateHostNameInvalid, suppressCertificateTimeInvalid, suppressCertificateChainIncomplete, suppressCertificateRevocationUnknown bool) error {
	if certificate == nil {
		return BadCertificateInvalid
	}

	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()
	trusted := []*x509.Certificate{}
	crls := []*x509.RevocationList{}

	if crts, err := readCertificates(issuersPath); err == nil {
		for _, crt := range crts {
			if isSelfSigned(crt) {
				roots.AddCert(crt)
			} else {
				intermediates.AddCert(crt)
			}
		}
	}

	if lists, err := readRevocationLists(issuersCRLPath); err == nil {
		crls = append(crls, lists...)
	}

	if crts, err := readCertificates(trustedPath); err == nil {
		trusted = crts
		for _, crt := range crts {
			if isSelfSigned(crt) {
				roots.AddCert(crt)
			} else {
				intermediates.AddCert(crt)
			}
		}
	}

	if lists, err := readRevocationLists(trustedCRLPath); err == nil {
		crls = append(crls, lists...)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     keyUsages,
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
		trusted = append(trusted, certificate)
	}

	// build chain
	chains, err := certificate.Verify(opts)
	switch se := err.(type) {
	case x509.CertificateInvalidError:
		switch se.Reason {
		case x509.Expired:
			// this is just to pass test 033 of Security Certificate Validation
			// UnknownAuthorityErrors should have priority over CertificateInvalidErrors
			opts.CurrentTime = certificate.NotBefore
			if _, err1 := certificate.Verify(opts); err1 == nil {
				err = BadCertificateTimeInvalid
			} else {
				err = BadSecurityChecksFailed
			}
		case x509.IncompatibleUsage:
			err = BadCertificateUseNotAllowed
		default:
			err = BadSecurityChecksFailed
		}
	case x509.HostnameError:
		err = BadCertificateHostNameInvalid
	case x509.UnknownAuthorityError:
		err = BadSecurityChecksFailed
	}

	if err == nil {
		for _, chain := range chains {
			chainMemberTrusted := false
			for j, c := range chain {

				//LogInfo.Printf("[%d][%d] %s", i, j, c.Subject.String())

				// check signature if self-signed (otherwise the signatures are checked when building chain?)
				if isSelfSigned(c) {
					err2 := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
					if err2 != nil {
						err = BadSecurityChecksFailed
						break
					}
				}

				// check security policy

				// check trust list
				if !chainMemberTrusted {
				outer:
					for _, c2 := range chain {
						for _, c3 := range trusted {
							if c2.Equal(c3) {
								chainMemberTrusted = true
								break outer
							}
						}
					}
				}
				if !chainMemberTrusted {
					err = BadSecurityChecksFailed
					break
				}

				// check validity period

				// check hostname

				// check URI
				// if endpoint != nil {
				// 	uriValid := false
				// 	for _, uri := range c.URIs {
				// 		if uri.String() == endpoint.Server.ApplicationUri {
				// 			uriValid = true
				// 		}
				// 	}
				// 	if !uriValid {
				// 		err = BadCertificateUriInvalid
				// 		break
				// 	}
				// }

				// check certificate usage
				useValid := false
				if j == 0 { // is leaf
					for _, eku := range c.ExtKeyUsage {
						if eku == x509.ExtKeyUsageServerAuth {
							useValid = true
						}
					}
					if !useValid {
						err = BadCertificateUseNotAllowed
						break
					}
				} else {
					if c.KeyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign {
						useValid = true
					}
					if !useValid {
						err = BadCertificateIssuerUseNotAllowed
						break
					}
				}

				// find issuer revocation list, check revocation
				err = checkRevocation(chain, j, crls, suppressCertificateRevocationUnknown)
				if err != nil {
					if err == BadCertificateRevoked || err == BadCertificateIssuerRevoked {
						err = BadSecurityChecksFailed
					}
					break
				}
			}

			// this chain passed all checks
			if err == nil {
				break // no need to validate next chain
			}
		}
	}
	if err != nil {
		// log.Printf("Error verifying remote certificate. %s\n", err)
		if len(rejectedCertsPath) > 0 {
			os.MkdirAll(rejectedCertsPath, os.ModeDir|0755)
			block := &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}
			thumbprint := sha1.Sum(certificate.Raw)
			if f, err := os.Create(filepath.Join(rejectedCertsPath, fmt.Sprintf("%x.crt", thumbprint))); err == nil {
				pem.Encode(f, block)
				defer f.Close()
			}
		}
		return err
	}
	return nil
}

// readCertificates reads certificates from path.
// Path may be to a file, comma-separated list of files, or directory.
func readCertificates(path string) ([]*x509.Certificate, error) {
	fi, err := os.Stat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	files := make([]string, 0, 16)
	if fi != nil && fi.IsDir() {
		fis, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, fi := range fis {
			files = append(files, filepath.Join(path, fi.Name()))
		}
	} else {
		files = strings.Split(path, ",")
		for i := range files {
			files[i] = strings.TrimSpace(files[i])
		}
	}
	list := make([]*x509.Certificate, 0, 16)
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for len(buf) > 0 {
			var block *pem.Block
			block, buf = pem.Decode(buf)
			if block == nil {
				if crt, err := x509.ParseCertificate(buf); err == nil {
					list = append(list, crt)
				}
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			if crt, err := x509.ParseCertificate(block.Bytes); err == nil {
				list = append(list, crt)
			}
		}
	}
	return list, nil
}

// readRevocationLists reads certificate revocation lists from path.
// Path may be to a file, comma-separated list of files, or directory.
func readRevocationLists(path string) ([]*x509.RevocationList, error) {
	fi, err := os.Stat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	files := make([]string, 0, 16)
	if fi != nil && fi.IsDir() {
		fis, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, fi := range fis {
			files = append(files, filepath.Join(path, fi.Name()))
		}
	} else {
		files = strings.Split(path, ",")
		for i := range files {
			files[i] = strings.TrimSpace(files[i])
		}
	}
	list := make([]*x509.RevocationList, 0, 16)
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for len(buf) > 0 {
			var block *pem.Block
			block, buf = pem.Decode(buf)
			if block == nil {
				if crl, err := x509.ParseRevocationList(buf); err == nil {
					list = append(list, crl)
				}
				break
			}
			if block.Type != "X509 CRL" || len(block.Headers) != 0 {
				continue
			}
			if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
				list = append(list, crl)
			}
		}
	}
	return list, nil
}

// isSelfSigned returns true if the certificate is self-signed.
func isSelfSigned(certificate *x509.Certificate) bool {
	return bytes.Equal(certificate.RawIssuer, certificate.RawSubject)
}

// checkRevocation returns error if certificate was revoked, or revokation list was not found. 
func checkRevocation(chain []*x509.Certificate, index int, crls []*x509.RevocationList, suppressCertificateRevocationUnknown bool) error {
	if index+1 >= len(chain) {
		return nil
	}
	flag := false
	cert := chain[index]
	issuer := chain[index+1]
	isLeaf := index == 0
	for _, crl := range crls {
		if time.Now().Before(crl.NextUpdate) {
			if err := crl.CheckSignatureFrom(issuer); err == nil {
				flag = true
				for _, c := range crl.RevokedCertificates {
					if c.SerialNumber.Cmp(cert.SerialNumber) == 0 {
						if isLeaf {
							return BadCertificateRevoked
						}
						return BadCertificateIssuerRevoked
					}
				}
				break
			}
		}
	}
	if !flag && !suppressCertificateRevocationUnknown {
		if isLeaf {
			return BadCertificateRevocationUnknown
		}
		return BadCertificateIssuerRevocationUnknown
	}
	return nil
}
