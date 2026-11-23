// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// TestUserNameIdentityWithAShortPrivateExponent opens a session with a UserName
// identity on every endpoint of a server whose private exponent D is shorter than
// its modulus. Such a key is ordinary: about one 2048-bit key in thirty has a D whose
// top byte is zero. The encrypted password arrives in blocks of the modulus size, so
// a server that sizes its blocks by D cannot decrypt it, and each such server
// refuses every UserName session for as long as it keeps that key.
func TestUserNameIdentityWithAShortPrivateExponent(t *testing.T) {
	var key *rsa.PrivateKey
	for i := 0; i < 2000 && key == nil; i++ {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if len(k.D.Bytes()) < k.Size() {
			key = k
		}
	}
	if key == nil {
		t.Fatal("no 2048-bit key with a short private exponent in 2000 tries")
	}

	const port = 46012
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)
	appURI := fmt.Sprintf("urn:%s:shortexponent", host)
	certFile, keyFile := writeServerCertificate(t, key, appURI)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:  appURI,
			ApplicationName: ua.LocalizedText{Text: "shortexponent"},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		certFile,
		keyFile,
		endpointURL,
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithAuthenticateUserNameIdentityFunc(func(id ua.UserNameIdentity, _ string, _ string) error {
			if id.UserName != "root" || id.Password != "secret" {
				return ua.BadUserAccessDenied
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		<-served
	}()

	ctx := context.Background()
	var res *ua.GetEndpointsResponse
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if res, err = client.GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: endpointURL}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
	for _, e := range res.Endpoints {
		ch, err := client.Dial(
			ctx,
			endpointURL,
			client.WithSecurityPolicyURI(e.SecurityPolicyURI, e.SecurityMode),
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err != nil {
			t.Errorf("%s %s: %v", e.SecurityPolicyURI, e.SecurityMode, err)
			continue
		}
		ch.Close(ctx)
	}
}

// writeServerCertificate writes a self-signed certificate for key to a temporary
// directory and returns the certificate and key paths.
func writeServerCertificate(t *testing.T, key *rsa.PrivateKey, appURI string) (string, string) {
	t.Helper()
	uri, _ := url.Parse(appURI)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "shortexponent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
