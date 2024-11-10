// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"time"

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
)

type CustomStruct struct {
	W1 uint16
	W2 uint16
}

func init() {
	ua.RegisterBinaryEncodingID(reflect.TypeOf(CustomStruct{}), ua.ParseExpandedNodeID("nsu=http://github.com/awcullen/opcua/testserver/;i=12"))
}

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
	if err := nm.LoadNodeSetFromBuffer(testnodeset); err != nil {
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

	// add 'Matrix' variable
	varMatrix := server.NewVariableNode(
		srv,
		ua.NodeIDString{NamespaceIndex: 2, ID: "Demo.Static.Arrays.Matrix"},
		ua.QualifiedName{NamespaceIndex: 2, Name: "Matrix"},
		ua.LocalizedText{Text: "Matrix"},
		ua.LocalizedText{Text: "A matrix variable for testing."},
		nil,
		[]ua.Reference{ // add variable to 'Demo.Static.Arrays' folder
			{
				ReferenceTypeID: ua.ReferenceTypeIDOrganizes,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays")},
			},
		},
		ua.NewDataValue([][][]int32{{{0, 1, 2}, {3, 4, 5}, {6, 7, 8}, {9, 10, 11}}, {{12, 13, 14}, {15, 16, 17}, {18, 19, 20}, {21, 22, 23}}}, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		ua.DataTypeIDInt32,
		ua.ValueRankThreeDimensions,
		[]uint32{0, 0, 0}, // no maximum
		ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
		250.0,
		false,
		nil,
	)
	// add new nodes to namespace
	nm.AddNodes(
		typCustomStruct,
		varCustomStruct,
		varMatrix,
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

	return srv, nil
}

// getNextEventID gets next random eventID.
func getNextEventID() ua.ByteString {
	var nonce = make([]byte, 16)
	rand.Read(nonce)
	return ua.ByteString(nonce)
}
