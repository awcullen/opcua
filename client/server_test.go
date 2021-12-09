// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"
	"os"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/server"
	"golang.org/x/crypto/bcrypt"
)

const (
	port            = 46010
	SoftwareVersion = "0.9.0"
)

func NewTestServer() (*server.Server, error) {

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
		return nil, err
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer([]byte(testnodeset)); err != nil {
		return nil, err
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
	return srv, nil
}
