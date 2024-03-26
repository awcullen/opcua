// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"

	"github.com/pkg/errors"
)

var (
	endpointURL = fmt.Sprintf("opc.tcp://%s:%d", host, port) // our testserver
)

func TestServer(t *testing.T) {
	// generate client and server certificates
	serverCert, clientCert, err := createCertificates()
	if err != nil {
		t.Fatal(err)
	}

	// write certificates to ./pki
	// client certificates are needed for both tests, so write before both
	if err := writeCertificates(serverCert, clientCert); err != nil {
		t.Fatal(errors.Wrap(err, "Error creating pki"))
	}
	// delete ./pki after the test
	t.Cleanup(cleanupCertificates)

	for _, s := range []struct {
		with       string
		testServer func(t *testing.T) *server.Server
	}{
		{
			with: "key material stored as files",
			testServer: func(t *testing.T) *server.Server {
				srv, err := NewTestServer()
				if err != nil {
					t.Fatal(errors.Wrap(err, "Error constructing server"))
				}
				return srv
			},
		},
		{
			with: "key material provided within code",
			testServer: func(t *testing.T) *server.Server {
				srv, err := NewTestServerWithCertificate(serverCert)
				if err != nil {
					t.Fatal(errors.Wrap(err, "Error constructing server"))
				}
				return srv
			},
		},
	} {
		t.Run(s.with, func(t *testing.T) {
			srv := s.testServer(t)

			t.Cleanup(func() {
				srv.Close()
			})
			go func() {
				if err := srv.ListenAndServe(); err != ua.BadServerHalted {
					t.Error(errors.Wrap(err, "Error starting server"))
				}
			}()

			// Discovers connection information about a server.
			t.Run("discovery client", func(t *testing.T) {
				{
					res, err := client.FindServers(context.Background(), &ua.FindServersRequest{EndpointURL: endpointURL})
					if err != nil {
						t.Error(errors.Wrap(err, "Error calling FindServers"))
						return
					}
					t.Log("Success calling FindServers:")
					for _, a := range res.Servers {
						t.Logf(" + %s, %s", a.ApplicationName.Text, a.ApplicationURI)
					}
				}
				{
					res, err := client.GetEndpoints(context.Background(), &ua.GetEndpointsRequest{EndpointURL: endpointURL})
					if err != nil {
						t.Error(errors.Wrap(err, "Error calling GetEndpoints"))
						return
					}
					t.Logf("Success calling getEndpoints:")
					for _, e := range res.Endpoints {
						t.Logf(" + %s, %s, %s", e.EndpointURL, strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#"), e.SecurityMode)
						for _, tok := range e.UserIdentityTokens {
							t.Logf("   + %s, %s", tok.PolicyID, strings.TrimPrefix(tok.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#"))
						}
					}
				}
			})

			// Tests opening a connection with a server using no security.
			t.Run("open client without security", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithInsecureSkipVerify(), // skips verification of server certificate
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				t.Logf("  SecurityPolicyURI: %s", ch.SecurityPolicyURI())
				t.Logf("  SecurityMode: %s", ch.SecurityMode())
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
			})

			// Tests opening a connection with a server using the best security the server offers.
			t.Run("open client with security", func(t *testing.T) {
				ctx := context.Background()
				res, err := client.GetEndpoints(context.Background(), &ua.GetEndpointsRequest{EndpointURL: endpointURL})
				if err != nil {
					t.Error(errors.Wrap(err, "Error calling GetEndpoints"))
					return
				}
				t.Logf("Success calling getEndpoints:")
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
						t.Error(errors.Wrap(err, "Error connecting to server"))
						return
					}
					t.Logf("Success connecting to server: %s", ch.EndpointURL())
					t.Logf("  SecurityPolicyURI: %s", ch.SecurityPolicyURI())
					t.Logf("  SecurityMode: %s", ch.SecurityMode())
					err = ch.Close(ctx)
					if err != nil {
						t.Error(errors.Wrap(err, "Error closing client"))
						ch.Abort(ctx)
						return
					}
				}
			})

			// Tests reading the server status variable.
			t.Run("read server status", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				res, err := ch.Read(ctx, &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{
						{NodeID: ua.VariableIDServerServerStatus, AttributeID: ua.AttributeIDValue},
					},
				})
				if err != nil {
					t.Error(errors.Wrap(err, "Error reading"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				if res.Results[0].StatusCode.IsBad() {
					t.Error(errors.Wrap(res.Results[0].StatusCode, "Error reading ServerStatus"))
					return
				}
				status, ok := res.Results[0].Value.(ua.ServerStatusDataType)
				if !ok {
					t.Error(errors.New("Error decoding ServerStatusDataType"))
					return
				}
				t.Logf("Server status:")
				t.Logf("  ProductName: %s", status.BuildInfo.ProductName)
				t.Logf("  SoftwareVersion: %s", status.BuildInfo.SoftwareVersion)
				t.Logf("  ManufacturerName: %s", status.BuildInfo.ManufacturerName)
				t.Logf("  State: %s", status.State)
				t.Logf("  CurrentTime: %s", status.CurrentTime)
			})

			// Tests reading the server variables to demonstrate the built-in types available.
			t.Run("read builtin types", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithInsecureSkipVerify(),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Boolean"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.SByte"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int16"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int32"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int64"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Byte"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt16"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt32"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt64"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Float"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Double"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.String"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.DateTime"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Guid"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.ByteString"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.XmlElement"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.LocalizedText"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.QualifiedName"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Boolean"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.SByte"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int16"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int64"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Byte"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt16"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt32"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt64"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Float"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Double"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.String"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.DateTime"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Guid"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.ByteString"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.XmlElement"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.LocalizedText"), AttributeID: ua.AttributeIDValue},
						{NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.QualifiedName"), AttributeID: ua.AttributeIDValue},
					},
				}
				res, err := ch.Read(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error reading session status"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("Results:")
				for i, result := range res.Results {
					if result.StatusCode.IsGood() {
						t.Logf("%s: %v", req.NodesToRead[i].NodeID, result.Value)
					} else {
						t.Error(errors.Wrap(result.StatusCode, "Error reading node"))
					}
				}
			})

			// Tests reading various attributes of a server object.
			t.Run("read attributes", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{
						{NodeID: ua.ObjectIDServer, AttributeID: 1},
						{NodeID: ua.ObjectIDServer, AttributeID: 2},
						{NodeID: ua.ObjectIDServer, AttributeID: 3},
						{NodeID: ua.ObjectIDServer, AttributeID: 4},
						{NodeID: ua.ObjectIDServer, AttributeID: 5},
						{NodeID: ua.ObjectIDServer, AttributeID: 6},
						{NodeID: ua.ObjectIDServer, AttributeID: 7},
						{NodeID: ua.ObjectIDServer, AttributeID: 24},
						{NodeID: ua.ObjectIDServer, AttributeID: 25},
						{NodeID: ua.ObjectIDServer, AttributeID: 26},
						{NodeID: ua.ObjectIDServer, AttributeID: 12},
					},
				}
				res, err := ch.Read(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error reading server object"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("Results:")
				for i, result := range res.Results {
					if result.StatusCode.IsGood() {
						t.Logf("%d: %v", req.NodesToRead[i].AttributeID, result.Value)
					} else {
						t.Logf("%d: %s", req.NodesToRead[i].AttributeID, result.StatusCode)
					}
				}
			})

			// Tests writing the fourth and fifth elements of a server array variable.
			t.Run("write", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.WriteRequest{
					NodesToWrite: []ua.WriteValue{
						{
							NodeID:      ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Double"),
							AttributeID: ua.AttributeIDValue,
							Value:       ua.NewDataValue(float64(42.0), 0, time.Time{}, 0, time.Time{}, 0),
						},
					},
				}
				res, err := ch.Write(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error writing"))
					ch.Abort(ctx)
					return
				}
				if res.Results[0].IsBad() {
					t.Error(errors.Wrap(res.Results[0], "Error writing"))
					ch.Abort(ctx)
					return
				}
				t.Logf("%s: %s", req.NodesToWrite[0].NodeID, res.Results[0])
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
			})

			// Tests reading the first three elements of a server array variable.
			t.Run("read index range", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithInsecureSkipVerify(),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{
						{
							NodeID:      ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Double"),
							AttributeID: ua.AttributeIDValue,
							IndexRange:  "0:2",
						},
					},
				}
				res, err := ch.Read(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error reading"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("Results:")
				for i, result := range res.Results {
					t.Logf("%s: %v, %s", req.NodesToRead[i].NodeID, result.Value, result.StatusCode)
				}
			})

			// Tests writing the fourth and fifth elements of a server array variable.
			t.Run("write index range", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.WriteRequest{
					NodesToWrite: []ua.WriteValue{
						{
							NodeID:      ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32"),
							AttributeID: ua.AttributeIDValue,
							IndexRange:  "4:5",
							Value:       ua.NewDataValue([]int32{4, 5}, 0, time.Time{}, 0, time.Time{}, 0),
						},
					},
				}
				res, err := ch.Write(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error writing"))
					ch.Abort(ctx)
					return
				}
				if res.Results[0].IsBad() {
					t.Error(errors.Wrap(res.Results[0], "Error writing"))
					ch.Abort(ctx)
					return
				}
				t.Logf("%s: %s", req.NodesToWrite[0].NodeID, res.Results[0])
				req2 := &ua.ReadRequest{
					NodesToRead: []ua.ReadValueID{
						{
							NodeID:      ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32"),
							AttributeID: ua.AttributeIDValue,
							IndexRange:  "0:9",
						},
					},
				}
				res2, err := ch.Read(ctx, req2)
				if err != nil {
					t.Error(errors.Wrap(err, "Error reading"))
					ch.Abort(ctx)
					return
				}
				t.Logf("%s: %v", req2.NodesToRead[0].NodeID, res2.Results[0].Value)
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
			})

			// Tests browsing the top-level objects folder.
			t.Run("browse", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithInsecureSkipVerify(),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.BrowseRequest{
					NodesToBrowse: []ua.BrowseDescription{
						{
							NodeID:          ua.ParseNodeID("i=85"),
							BrowseDirection: ua.BrowseDirectionForward,
							ReferenceTypeID: ua.ReferenceTypeIDHierarchicalReferences,
							IncludeSubtypes: true,
							ResultMask:      uint32(ua.BrowseResultMaskAll),
						},
					},
				}
				res, err := ch.Browse(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error browsing"))
					ch.Abort(ctx)
					return
				}
				if res.Results[0].StatusCode.IsBad() {
					t.Error(errors.Wrap(res.Results[0].StatusCode, "Error browsing"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("Browse results of NodeID '%s':", req.NodesToBrowse[0].NodeID)
				for _, r := range res.Results[0].References {
					t.Logf(" + %s, browseName: %s, nodeClass: %s, nodeId: %s", r.DisplayName.Text, r.BrowseName, r.NodeClass, r.NodeID)
				}
			})

			// Tests subscribing to recieve data changes of the server's variable.
			t.Run("subscribe", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithInsecureSkipVerify(),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.CreateSubscriptionRequest{
					RequestedPublishingInterval: 1000.0,
					RequestedMaxKeepAliveCount:  30,
					RequestedLifetimeCount:      30 * 3,
					PublishingEnabled:           true,
				}
				res, err := ch.CreateSubscription(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error creating subscription"))
					ch.Abort(ctx)
					return
				}
				req2 := &ua.CreateMonitoredItemsRequest{
					SubscriptionID:     res.SubscriptionID,
					TimestampsToReturn: ua.TimestampsToReturnBoth,
					ItemsToCreate: []ua.MonitoredItemCreateRequest{
						{
							ItemToMonitor: ua.ReadValueID{
								AttributeID: ua.AttributeIDValue,
								NodeID:      ua.VariableIDServerServerStatusCurrentTime,
							},
							MonitoringMode: ua.MonitoringModeReporting,
							RequestedParameters: ua.MonitoringParameters{
								ClientHandle: 42, QueueSize: 1, DiscardOldest: true, SamplingInterval: 500.0,
							},
						},
					},
				}
				res2, err := ch.CreateMonitoredItems(ctx, req2)
				if err != nil {
					t.Error(errors.Wrap(err, "Error creating item"))
				}
				_ = res2
				// prepare an initial publish request
				req3 := &ua.PublishRequest{
					RequestHeader:                ua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{},
				}
				// loop until 3 data changes received.
				numChanges := 0
				for numChanges < 3 {
					res, err := ch.Publish(ctx, req3)
					if err != nil {
						t.Error(errors.Wrap(err, "Error publishing"))
						break
					}
					// loop thru all the notifications.
					for _, data := range res.NotificationMessage.NotificationData {
						switch body := data.(type) {
						case ua.DataChangeNotification:
							for _, z := range body.MonitoredItems {
								if z.ClientHandle == 42 {
									t.Logf(" + CurrentTime: %s", z.Value.Value)
									numChanges++
								}
							}
						}
					}
					// prepare another publish request
					req3 = &ua.PublishRequest{
						RequestHeader: ua.RequestHeader{TimeoutHint: 60000},
						SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{
							{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
						},
					}
				}
				// success after receiving 3 data changes.
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
			})

			// Tests calling a method of the server and passing Aurguments.
			t.Run("call method", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())

				req := &ua.CallRequest{
					MethodsToCall: []ua.CallMethodRequest{{
						ObjectID:       ua.ParseNodeID("ns=2;s=Demo.Methods"), // parent node
						MethodID:       ua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO"),
						InputArguments: []ua.Variant{uint32(uint32(6)), uint32(uint32(7))}},
					},
				}
				res, err := ch.Call(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error calling method"))
					ch.Abort(ctx)
					return
				}
				if res.Results[0].StatusCode.IsBad() {
					t.Error(errors.Wrap(res.Results[0].StatusCode, "Error calling method"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("  %6d", req.MethodsToCall[0].InputArguments[0])
				t.Logf("+ %6d", req.MethodsToCall[0].InputArguments[1])
				t.Logf("--------")
				t.Logf("  %6d", res.Results[0].OutputArguments[0])
			})

			// Tests finding a node in the namespace, given a starting nodeID and a BrowsePath.
			t.Run("translate", func(t *testing.T) {
				ctx := context.Background()
				ch, err := client.Dial(
					ctx,
					endpointURL,
					client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
					client.WithInsecureSkipVerify(),
					client.WithUserNameIdentity("root", "secret"),
				)
				if err != nil {
					t.Error(errors.Wrap(err, "Error connecting to server"))
					return
				}
				t.Logf("Success connecting to server: %s", ch.EndpointURL())
				req := &ua.TranslateBrowsePathsToNodeIDsRequest{
					BrowsePaths: []ua.BrowsePath{
						{
							StartingNode: ua.ParseNodeID("ns=2;s=Demo"),
							RelativePath: ua.RelativePath{
								Elements: []ua.RelativePathElement{
									{TargetName: ua.ParseQualifiedName("2:Static")},
									{TargetName: ua.ParseQualifiedName("2:Scalar")},
									{TargetName: ua.ParseQualifiedName("2:Float")},
								},
							},
						},
					},
				}
				res, err := ch.TranslateBrowsePathsToNodeIDs(ctx, req)
				if err != nil {
					t.Error(errors.Wrap(err, "Error TranslateBrowsePathsToNodeIDs"))
					ch.Abort(ctx)
					return
				}
				err = ch.Close(ctx)
				if err != nil {
					t.Error(errors.Wrap(err, "Error closing client"))
					ch.Abort(ctx)
					return
				}
				t.Logf("Results:")
				for i, r := range res.Results {
					if r.StatusCode.IsGood() {
						t.Logf("%s: %d", req.BrowsePaths[i].StartingNode, len(r.Targets))
						for _, target := range r.Targets {
							t.Logf("  %s: %d", target.TargetID, target.RemainingPathIndex)
						}
					} else {
						t.Logf("code: %s", r.StatusCode)
						t.Logf("%s: %d", req.BrowsePaths[i].StartingNode, len(r.Targets))
						for _, target := range r.Targets {
							t.Logf("  %s: %d", target.TargetID, target.RemainingPathIndex)
						}
						t.Error("Error TranslateBrowsePath")
					}
				}
			})
		})
	}
}

/*
// TestReadHistory demonstrates reading history from the UaCPPServer available from https://www.unified-automation.com/
func TestReadHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long running test")
	}
	ctx := context.Background()
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:48010",
		client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
		client.WithInsecureSkipVerify(), // skips verification of server certificate
		client.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error connecting to server"))
		return
	}
	t.Logf("Success connecting to server: %s", ch.EndpointURL())

	t.Logf("Start logging of data...")
	req := &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{
			{
				ObjectID:       ua.ParseNodeID("ns=2;s=Demo.History"), // parent node
				MethodID:       ua.ParseNodeID("ns=2;s=Demo.History.StartLogging"),
				InputArguments: []ua.Variant{},
			},
		},
	}

	res, err := ch.Call(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error calling method"))
		ch.Abort(ctx)
		return
	}
	_ = res

	t.Logf("Collecting 10 seconds of data...")
	time.Sleep(10 * time.Second)

	t.Log("Reading history for last 10 seconds")
	var cp ua.ByteString
	for {
		req2 := &ua.HistoryReadRequest{
			HistoryReadDetails: ua.ReadRawModifiedDetails{
				StartTime:        time.Now().Add(-1 * time.Minute),
				EndTime:          time.Now(),
				NumValuesPerNode: 100,
				ReturnBounds:     false,
			},
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: false,
			NodesToRead: []ua.HistoryReadValueID{
				{NodeID: ua.ParseNodeID("ns=2;s=Demo.History.DoubleWithHistory"), ContinuationPoint: cp},
			},
		}

		res2, err := ch.HistoryRead(ctx, req2)
		if err != nil {
			t.Error(errors.Wrap(err, "Error reading"))
			ch.Abort(ctx)
			return
		}

		if res2.Results[0].StatusCode.IsBad() {
			t.Errorf("Error reading values for node '%s'. %s", req2.NodesToRead[0].NodeID, res2.Results[0].StatusCode)
			ch.Abort(ctx)
			return
		}

		if historyData, ok := res2.Results[0].HistoryData.(ua.HistoryData); ok {
			t.Logf("Found %d value(s) for node '%s':", len(historyData.DataValues), req2.NodesToRead[0].NodeID)
			for _, result := range historyData.DataValues {
				t.Logf("Read %v, q: %#X, ts: %s", result.Value, uint32(result.StatusCode), result.SourceTimestamp)
			}
		}

		cp = res2.Results[0].ContinuationPoint
		if cp == "" {
			break
		}
	}
	t.Log("Now read the 1 sec average of the last 10 seconds...")

	req3 := &ua.HistoryReadRequest{
		HistoryReadDetails: ua.ReadProcessedDetails{
			StartTime:          time.Now().Add(-10 * time.Second),
			EndTime:            time.Now(),
			ProcessingInterval: 1000.0,
			AggregateType:      []ua.NodeID{ua.ObjectIDAggregateFunctionAverage},
		},
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []ua.HistoryReadValueID{
			{NodeID: ua.ParseNodeID("ns=2;s=Demo.History.DoubleWithHistory")},
		},
	}

	res3, err := ch.HistoryRead(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}

	if res3.Results[0].StatusCode.IsBad() {
		t.Errorf("Error reading values for node '%s'. %s", req3.NodesToRead[0].NodeID, res3.Results[0].StatusCode)
		ch.Abort(ctx)
		return
	}

	if historyData, ok := res3.Results[0].HistoryData.(ua.HistoryData); ok {
		t.Logf("Found %d average value(s) for node '%s':", len(historyData.DataValues), req3.NodesToRead[0].NodeID)
		for _, result := range historyData.DataValues {
			t.Logf("Read %v, q: %#X, ts: %s", result.Value, uint32(result.StatusCode), result.SourceTimestamp)
		}
	}

	t.Logf("Stop logging of data...")
	req4 := &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{{
			ObjectID:       ua.ParseNodeID("ns=2;s=Demo.History"), // parent node
			MethodID:       ua.ParseNodeID("ns=2;s=Demo.History.StopLogging"),
			InputArguments: []ua.Variant{}},
		},
	}

	res4, err := ch.Call(ctx, req4)
	if err != nil {
		t.Error(errors.Wrap(err, "Error calling method"))
		ch.Abort(ctx)
		return
	}
	_ = res4

	ch.Close(ctx)
}
*/

func createNewCertificate(appName string) (tls.Certificate, error) {

	// Create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return tls.Certificate{}, ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Create a certificate.
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
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{localAddr.IP, []byte{127, 0, 0, 1}},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, ua.BadCertificateInvalid
	}

	return tls.Certificate{
		PrivateKey:  key,
		Certificate: [][]byte{rawcrt},
	}, nil
}

func writeCertificate(cert tls.Certificate, certFile, keyFile string) error {
	if f, err := os.Create(certFile); err == nil {
		defer f.Close()
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
		if err := pem.Encode(f, block); err != nil {
			return err
		}
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		defer f.Close()
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}
		if err := pem.Encode(f, block); err != nil {
			return err
		}
	} else {
		return err
	}

	return nil
}

func createCertificates() (server tls.Certificate, client tls.Certificate, err error) {
	client, err = createNewCertificate("test-client")
	if err != nil {
		return
	}
	server, err = createNewCertificate("testserver")
	if err != nil {
		return
	}
	return
}

const pkiPath = "./pki"

func writeCertificates(server tls.Certificate, client tls.Certificate) error {
	// check if ./pki already exists
	if _, err := os.Stat(pkiPath); !os.IsNotExist(err) {
		return nil
	}

	// make a pki directory, if not exist
	if err := os.MkdirAll(pkiPath, os.ModeDir|0755); err != nil {
		return err
	}

	// create a client cert in ./pki
	if err := writeCertificate(client, filepath.Join(pkiPath, "client.crt"), filepath.Join(pkiPath, "client.key")); err != nil {
		return err
	}

	// create a server cert in ./pki
	if err := writeCertificate(server, filepath.Join(pkiPath,"server.crt"), filepath.Join(pkiPath,"server.key")); err != nil {
		return err
	}

	return nil
}

func cleanupCertificates() {
	os.RemoveAll(pkiPath)
}
