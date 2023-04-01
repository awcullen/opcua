// Copyright 2021 Converter Systems LLC. All rights reserved.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var (
	host, _         = os.Hostname()
	port            = 46010
	SoftwareVersion = "0.3.0"
	//go:embed nodeset.xml
	nodeset []byte
)

type CustomStruct struct {
	W1 uint16
	W2 uint16
}

func init() {
	ua.RegisterBinaryEncodingID(reflect.TypeOf(CustomStruct{}), ua.ParseExpandedNodeID("nsu=http://github.com/awcullen/opcua/testserver/;i=12"))
}

func main() {

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// create directory with certificate and key, if not found.
	if err := ensurePKI(); err != nil {
		log.Println("Error creating PKI.")
		return
	}

	// userids for testing
	userids := []ua.UserNameIdentity{
		{UserName: "root", Password: "secret"},
		{UserName: "user1", Password: "password"},
		{UserName: "user2", Password: "password1"},
	}
	for i := range userids {
		hash, _ := bcrypt.GenerateFromPassword([]byte(userids[i].Password), 8)
		userids[i].Password = string(hash)
	}

	// create the endpoint url from hostname and port
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)

	// create server
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("testserver@%s", host),
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  SoftwareVersion,
			}),
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			log.Printf("Login anonymous identity from %s\n", applicationURI)
			return nil
		}),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
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
				return ua.BadUserAccessDenied
			}
			log.Printf("Login %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithAuthenticateX509IdentityFunc(func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
			cert, err := x509.ParseCertificate([]byte(userIdentity.Certificate))
			if err != nil {
				return ua.BadUserAccessDenied
			}
			log.Printf("Login %s from %s\n", cert.Subject, applicationURI)
			return nil
		}),
		server.WithSecurityPolicyNone(true),
		//server.WithInsecureSkipVerify(),
		server.WithTrustedCertificatesFile("./pki/trusted.crt"),
		server.WithServerDiagnostics(true),
		server.WithMaxSessionCount(50),
		// server.WithTrace(),
	)
	if err != nil {
		os.Exit(1)
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer(nodeset); err != nil {
		os.Exit(2)
	}

	// install MethodNoArgs method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodNoArgs")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			return ua.CallMethodResult{}
		})
	}

	// install MethodI method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodI")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			statusCode := ua.Good
			inputArgumentResults := make([]ua.StatusCode, 1)
			_, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[0] = ua.BadTypeMismatch
			}
			if statusCode == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			return ua.CallMethodResult{OutputArguments: []ua.Variant{}}
		})
	}

	// install MethodO method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodO")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) > 0 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			result := uint32(42)
			return ua.CallMethodResult{OutputArguments: []ua.Variant{uint32(result)}}
		})
	}

	// install MethodIO method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 2 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 2 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			statusCode := ua.Good
			inputArgumentResults := make([]ua.StatusCode, 2)
			a, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[0] = ua.BadTypeMismatch
			}
			b, ok := req.InputArguments[1].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[1] = ua.BadTypeMismatch
			}
			if statusCode == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			result := a + b
			return ua.CallMethodResult{OutputArguments: []ua.Variant{uint32(result)}}
		})
	}

	// add 'CustomStruct' data type
	typCustomStruct := server.NewDataTypeNode(
		srv,
		ua.NodeIDNumeric{NamespaceIndex: 2, ID: 13},
		ua.QualifiedName{NamespaceIndex: 2, Name: "CustomStruct"},
		ua.LocalizedText{Text: "CustomStruct"},
		ua.LocalizedText{Text: "A CustomStruct data type for testing."},
		nil,
		[]ua.Reference{ // add type as subtype of 'Structure'
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasSubtype,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.DataTypeIDStructure},
			},
		},
		false,
		// this definition allows browsers such as UAExpert to decode the CustomStruct
		ua.StructureDefinition{
			DefaultEncodingID: ua.NodeIDNumeric{NamespaceIndex: 2, ID: 12},
			BaseDataType:      ua.DataTypeIDStructure,
			StructureType:     ua.StructureTypeStructure,
			Fields: []ua.StructureField{
				{Name: "W1", DataType: ua.DataTypeIDUInt16, ValueRank: ua.ValueRankScalar},
				{Name: "W2", DataType: ua.DataTypeIDUInt16, ValueRank: ua.ValueRankScalar},
			},
		},
	)

	// add 'CustomStruct' variable
	varCustomStruct := server.NewVariableNode(
		srv,
		ua.NodeIDNumeric{NamespaceIndex: 2, ID: 14},
		ua.QualifiedName{NamespaceIndex: 2, Name: "CustomStruct"},
		ua.LocalizedText{Text: "CustomStruct"},
		ua.LocalizedText{Text: "A CustomStruct variable for testing."},
		nil,
		[]ua.Reference{ // add variable to 'Demo.Static.Scalar' folder
			{
				ReferenceTypeID: ua.ReferenceTypeIDOrganizes,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar")},
			},
		},
		ua.NewDataValue(CustomStruct{W1: 1, W2: 2}, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		typCustomStruct.NodeID(),
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
		250.0,
		false,
		nil,
	)

	// add new nodes to namespace
	nm.AddNodes(
		typCustomStruct,
		varCustomStruct,
	)

	go func() {
		source, _ := nm.FindObject(ua.ParseNodeID("ns=2;s=Area1"))
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				evt := &ua.BaseEvent{
					EventID:     getNextEventID(),
					EventType:   ua.ObjectTypeIDBaseEventType,
					SourceNode:  source.NodeID(),
					SourceName:  "Area1",
					Time:        time.Now(),
					ReceiveTime: time.Now(),
					Message:     ua.LocalizedText{Text: "Event in Area1"},
					Severity:    500,
				}
				nm.OnEvent(source, evt)
			case <-srv.Closing():
				return
			}
		}
	}()

	go func() {
		active, acked := true, false
		source, _ := nm.FindObject(ua.ParseNodeID("ns=2;s=Area2"))

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				evt := &ua.AlarmCondition{
					EventID:       getNextEventID(),
					EventType:     ua.ObjectTypeIDAlarmConditionType,
					SourceNode:    source.NodeID(),
					SourceName:    "Area2",
					Time:          time.Now(),
					ReceiveTime:   time.Now(),
					Message:       ua.LocalizedText{Text: "Alarm in Area2"},
					ConditionID:   ua.ObjectTypeIDOffNormalAlarmType,
					ConditionName: "OffNormalAlarm",
					Severity:      500,
					Retain:        true,
					AckedState:    acked,
					ActiveState:   active,
				}
				nm.OnEvent(source, evt)
				if !active {
					active = true
				} else {
					if !acked {
						acked = true
					} else {
						active, acked = false, false
					}
				}

			case <-srv.Closing():
				return
			}
		}
	}()

	go func() {
		// wait for signal (this conflicts with debugger currently)
		log.Println("Press Ctrl-C to exit...")
		waitForSignal()

		log.Println("Stopping server...")
		srv.Close()
	}()

	// start server
	log.Printf("Starting server '%s' at '%s'\n", srv.LocalDescription().ApplicationName.Text, srv.EndpointURL())
	if err := srv.ListenAndServe(); err != ua.BadServerHalted {
		log.Println(errors.Wrap(err, "Error starting server"))
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
		return ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// create a certificate.
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName, ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: host}}},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{localAddr.IP},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return ua.BadCertificateInvalid
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

// getNextEventID gets next random eventID.
func getNextEventID() ua.ByteString {
	var nonce = make([]byte, 16)
	rand.Read(nonce)
	return ua.ByteString(nonce)
}
