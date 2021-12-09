// Copyright 2021 Converter Systems LLC. All rights reserved.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/server"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	port            = 46010
	SoftwareVersion = "0.9.0"
)

func main() {
	// open http://localhost:6060/debug/pprof/ in your browser.
	go func() {
		go log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// create directory with certificate and key, if not found.
	if err := ensurePKI(); err != nil {
		log.Println("Error creating PKI.")
		return
	}

	// local hostname
	host, _ := os.Hostname()

	// userids for testing
	userids := []opcua.UserNameIdentity{
		{UserName: "root", Password: "secret"},
		{UserName: "user1", Password: "password"},
		{UserName: "user2", Password: "password1"},
	}
	for i := range userids {
		hash, _ := bcrypt.GenerateFromPassword([]byte(userids[i].Password), 8)
		userids[i].Password = string(hash)
	}

	// create server
	srv, err := server.New(
		opcua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua/testserver",
			ApplicationName: opcua.LocalizedText{
				Text:   fmt.Sprintf("testserver@%s", host),
				Locale: "en",
			},
			ApplicationType:     opcua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{fmt.Sprintf("opc.tcp://%s:%d", host, port)},
		},
		"./pki/server.crt",
		"./pki/server.key",
		fmt.Sprintf("opc.tcp://%s:%d", host, port),
		server.WithBuildInfo(
			opcua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua/testserver",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  SoftwareVersion,
			}),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity opcua.UserNameIdentity, applicationURI string, endpointURL string) error {
			valid := false
			for _, user := range userids {
				if user.UserName == userIdentity.UserName {
					if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userIdentity.Password)); err == nil {
						valid = true
						break
					}
				}
			}
			if !valid {
				return opcua.BadUserAccessDenied
			}
			// log.Printf("Login user: %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithRolesProvider(
			server.NewRulesBasedRolesProvider(
				[]server.IdentityMappingRule{
					// WellKnownRoleAnonymous
					{
						NodeID: opcua.ObjectIDWellKnownRoleAnonymous,
						Identities: []opcua.IdentityMappingRuleType{
							{CriteriaType: opcua.IdentityCriteriaTypeAnonymous},
						},
						ApplicationsExclude: true,
						EndpointsExclude:    true,
					},
					// WellKnownRoleAuthenticatedUser
					{
						NodeID: opcua.ObjectIDWellKnownRoleAuthenticatedUser,
						Identities: []opcua.IdentityMappingRuleType{
							{CriteriaType: opcua.IdentityCriteriaTypeAuthenticatedUser},
						},
						ApplicationsExclude: true,
						EndpointsExclude:    true,
					},
					// WellKnownRoleObserver
					{
						NodeID: opcua.ObjectIDWellKnownRoleObserver,
						Identities: []opcua.IdentityMappingRuleType{
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "user1"},
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "user2"},
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "root"},
						},
						ApplicationsExclude: true,
						EndpointsExclude:    true,
					},
					// WellKnownRoleOperator
					{
						NodeID: opcua.ObjectIDWellKnownRoleOperator,
						Identities: []opcua.IdentityMappingRuleType{
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "user1"},
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "user2"},
							{CriteriaType: opcua.IdentityCriteriaTypeUserName, Criteria: "root"},
						},
						ApplicationsExclude: true,
						EndpointsExclude:    true,
					},
				},
			),
		),
		server.WithRegistrationInterval(0.0),
		server.WithInsecureSkipVerify(),
		server.WithServerDiagnostics(true),
		// server.WithTrace(),
	)
	if err != nil {
		os.Exit(1)
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer([]byte(nodeset)); err != nil {
		os.Exit(2)
	}

	// install MethodNoArgs method
	if n, ok := nm.FindMethod(opcua.ParseNodeID("ns=2;s=Demo.Methods.MethodNoArgs")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			return opcua.CallMethodResult{}
		})
	}

	// install MethodI method
	if n, ok := nm.FindMethod(opcua.ParseNodeID("ns=2;s=Demo.Methods.MethodI")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			statusCode := opcua.Good
			inputArgumentResults := make([]opcua.StatusCode, 1)
			_, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = opcua.BadInvalidArgument
				inputArgumentResults[0] = opcua.BadTypeMismatch
			}
			if statusCode == opcua.BadInvalidArgument {
				return opcua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{}}
		})
	}

	// install MethodO method
	if n, ok := nm.FindMethod(opcua.ParseNodeID("ns=2;s=Demo.Methods.MethodO")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) > 0 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			result := uint32(42)
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{uint32(result)}}
		})
	}

	// install MethodIO method
	if n, ok := nm.FindMethod(opcua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) < 2 {
				return opcua.CallMethodResult{StatusCode: opcua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 2 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			statusCode := opcua.Good
			inputArgumentResults := make([]opcua.StatusCode, 2)
			a, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = opcua.BadInvalidArgument
				inputArgumentResults[0] = opcua.BadTypeMismatch
			}
			b, ok := req.InputArguments[1].(uint32)
			if !ok {
				statusCode = opcua.BadInvalidArgument
				inputArgumentResults[1] = opcua.BadTypeMismatch
			}
			if statusCode == opcua.BadInvalidArgument {
				return opcua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			result := a + b
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{uint32(result)}}
		})
	}

	go func() {
		// wait for signal (this conflicts with debugger currently)
		log.Println("Press Ctrl-C to exit...")
		waitForSignal()

		log.Println("Stopping server...")
		srv.Close()
	}()

	// open server
	log.Printf("Starting server '%s' at '%s'\n", srv.LocalDescription().ApplicationName.Text, srv.EndpointURL())
	if err := srv.ListenAndServe(); err != opcua.BadServerHalted {
		log.Println(errors.Wrap(err, "Error opening server"))
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func createNewCertificate(appName, certFile, keyFile string) error {

	// create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return opcua.BadCertificateInvalid
	}

	// create a certificate.
	host, _ := os.Hostname()
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return opcua.BadCertificateInvalid
	}

	if f, err := os.Create(certFile); err == nil {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: rawcrt}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	return nil
}

func ensurePKI() error {

	// check if ./pki already exists
	if _, err := os.Stat("./pki"); !os.IsNotExist(err) {
		return nil
	}

	// make a pki directory, if not exist
	if err := os.MkdirAll("./pki", os.ModeDir|0755); err != nil {
		return err
	}

	// create a server cert in ./pki/server.crt
	if err := createNewCertificate("testserver", "./pki/server.crt", "./pki/server.key"); err != nil {
		return err
	}

	return nil
}
