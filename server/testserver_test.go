// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"golang.org/x/crypto/bcrypt"
)

var (
	host, _         = os.Hostname()
	port            = 46010
	SoftwareVersion = "1.0.0"
	//go:embed testnodeset_test.xml
	testnodeset []byte
	dynamicNode server.Node
)

func NewTestServer() (*server.Server, error) {

	// userids for testing
	userids := []ua.UserNameIdentity{
		{UserName: "root", Password: "secret"},
		{UserName: "user1", Password: "password"},
		{UserName: "user2", Password: "password1"},
		// 72 bytes, the longest bcrypt takes, and over the 64 that a user name token used to carry.
		{UserName: "longpw", Password: "0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	}
	for i := range userids {
		hash, _ := bcrypt.GenerateFromPassword([]byte(userids[i].Password), 8)
		userids[i].Password = string(hash)
	}

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
			DiscoveryURLs:       []string{fmt.Sprintf("opc.tcp://%s:%d", host, port)},
		},
		"./pki/server.crt",
		"./pki/server.key",
		fmt.Sprintf("opc.tcp://%s:%d", host, port),
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  SoftwareVersion,
			}),
		server.WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			// log.Printf("Login anonymous identity from %s\n", applicationURI)
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
			// log.Printf("Login %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithAuthenticateX509IdentityFunc(func(userIdentity ua.X509Identity, applicationURI string, endpointURL string) error {
			_, err := x509.ParseCertificates([]byte(userIdentity.Certificate))
			if err != nil {
				return ua.BadUserAccessDenied
			}
			// log.Printf("Login %s from %s\n", cert.Subject, applicationURI)
			return nil
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
	)
	if err != nil {
		return nil, err
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer([]byte(testnodeset)); err != nil {
		return nil, err
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

	// install CreateDynamicNode method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.DynamicNodes.CreateDynamicNode")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if dynamicNode != nil {
				return ua.CallMethodResult{StatusCode: ua.BadInvalidState}
			}
			// create node
			dynamicNode = server.NewVariableNode(
				srv,
				ua.NewNodeIDString(2, "Demo.DynamicNodes.DynamicNode"),
				ua.NewQualifiedName(2, "DynamicNode"),
				ua.NewLocalizedText("DynamicNode", "en"),
				ua.NewLocalizedText("Variable node for testing", "en"),
				nil,
				[]ua.Reference{
					{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
					{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.NewExpandedNodeID(ua.NewNodeIDString(2, "Demo.DynamicNodes"))},
				},
				ua.DataValue{Value: int32(42)},
				ua.DataTypeIDInt32,
				ua.ValueRankScalar,
				nil,
				ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
				300.0,
				false,
				nil,
			)
			nm.AddNodes(dynamicNode)
			return ua.CallMethodResult{}
		})
	}

	// install DeleteDynamicNode method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.DynamicNodes.DeleteDynamicNode")); ok {
		n.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if dynamicNode == nil {
				return ua.CallMethodResult{StatusCode: ua.BadInvalidState}
			}
			nm.DeleteNodes(dynamicNode.NodeID())
			dynamicNode = nil
			return ua.CallMethodResult{}
		})
	}

	return srv, nil
}
