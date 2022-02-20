// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"golang.org/x/crypto/bcrypt"
)

var (
	host, _         = os.Hostname()
	port            = 46010
	SoftwareVersion = "0.3.0"
)

func NewTestServer() (*server.Server, error) {

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
			// log.Printf("Login user: %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithAnonymousIdentity(true),
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
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			return ua.CallMethodResult{}
		})
	}

	// install MethodI method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodI")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
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
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) > 0 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			result := uint32(42)
			return ua.CallMethodResult{OutputArguments: []ua.Variant{uint32(result)}}
		})
	}

	// install MethodIO method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
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

	return srv, nil
}

// getNextEventID gets next random eventID.
func getNextEventID() ua.ByteString {
	var nonce = make([]byte, 16)
	rand.Read(nonce)
	return ua.ByteString(nonce)
}
