package ua

import (
	"crypto/x509"
	"encoding/pem"
)

// CertificateList is a set of certificates.
type CertificateList struct {
	bySubjectKeyID map[string][]int
	byName         map[string][]int
	certs          []*x509.Certificate
}

// NewCertificateList returns a new, empty CertificateList.
func NewCertificateList() *CertificateList {
	return &CertificateList{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

// FindPotentialParents returns the certificates which might have signed cert.
func (s *CertificateList) FindPotentialParents(cert *x509.Certificate) []*x509.Certificate {
	if s == nil {
		return nil
	}
	if len(cert.AuthorityKeyId) > 0 {
		ids := s.bySubjectKeyID[string(cert.AuthorityKeyId)]
		res := make([]*x509.Certificate, len(ids))
		for i, j := range ids {
			res[i] = s.certs[j]
		}
		return res
	}
	ids := s.byName[string(cert.RawIssuer)]
	res := make([]*x509.Certificate, len(ids))
	for i, j := range ids {
		res[i] = s.certs[j]
	}
	return res
}

// Contains returns true if the list contains the certificate.
func (s *CertificateList) Contains(cert *x509.Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[string(cert.RawSubject)]
	for _, c := range candidates {
		if s.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a list.
func (s *CertificateList) AddCert(cert *x509.Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertificateList")
	}

	// Check that the certificate isn't being added twice.
	if s.Contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyID := string(cert.SubjectKeyId)
		s.bySubjectKeyID[keyID] = append(s.bySubjectKeyID[keyID], n)
	}
	name := string(cert.RawSubject)
	s.byName[name] = append(s.byName[name], n)
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertificateList) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertificateList) Subjects() [][]byte {
	res := make([][]byte, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.RawSubject
	}
	return res
}
