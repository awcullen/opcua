// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	ua "github.com/awcullen/opcua"
	"github.com/pkg/errors"
)

var (
	ep = "opc.tcp://127.0.0.1:48010" // unified-automation
)

func TestDiscoveryClient(t *testing.T) {
	{
		res, err := ua.FindServers(context.Background(), &ua.FindServersRequest{EndpointURL: ep})
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
		res, err := ua.GetEndpoints(context.Background(), &ua.GetEndpointsRequest{EndpointURL: ep})
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
}

func TestOpenClientlWithoutSecurity(t *testing.T) {
	//ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithUserNameIdentity("root", "secret"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	ch.Close(ctx)
}

func TestOpenClientWithSecurity(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	t.Logf("  SecurityPolicyURI: %s", ch.SecurityPolicyURI())
	t.Logf("  SecurityMode: %s", ch.SecurityMode())
	ch.Close(ctx)
}

func TestReadServerStatus(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	res, err := ch.Read(ctx, &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.VariableIDServerServerStatus, AttributeID: ua.AttributeIDValue}},
	})
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading session status"))
		ch.Abort(ctx)
		return
	}
	ch.Close(ctx)
	if res.Results[0].StatusCode().IsBad() {
		t.Error(errors.Wrap(res.Results[0].StatusCode(), "Error reading session status"))
		return
	}
	serverStatus, ok := res.Results[0].Value().(*ua.ServerStatusDataType)
	if !ok {
		t.Error(errors.Wrap(err, "Error decoding"))
		return
	}
	t.Logf("Server status:")
	t.Logf("  ProductName: %s", serverStatus.BuildInfo.ProductName)
	t.Logf("  SoftwareVersion: %s", serverStatus.BuildInfo.SoftwareVersion)
	t.Logf("  ManufacturerName: %s", serverStatus.BuildInfo.ManufacturerName)
	t.Logf("  State: %s", serverStatus.State)
	t.Logf("  CurrentTime: %s", serverStatus.CurrentTime)
}

func TestReadServerCurrentTime(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{NodeID: ua.VariableIDServerServerStatusCurrentTime, AttributeID: ua.AttributeIDValue},
		},
	}
	res, err := ch.Read(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading current time"))
		ch.Abort(ctx)
		return
	}
	if res.Results[0].StatusCode().IsBad() {
		t.Error(errors.Wrap(res.Results[0].StatusCode(), "Error reading current time"))
		ch.Abort(ctx)
		return
	}
	t.Logf(" + CurrentTime: %s", res.Results[0].Value().(time.Time))
	ch.Close(ctx)
}

func TestReadBuiltinTypes(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Boolean")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.SByte")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int16")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int32")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Int64")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Byte")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt16")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt32")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.UInt64")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Float")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Double")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.String")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.DateTime")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Guid")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.ByteString")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.XmlElement")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.LocalizedText")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.QualifiedName")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Boolean")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.SByte")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int16")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int64")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Byte")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt16")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt32")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.UInt64")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Float")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Double")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.String")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.DateTime")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Guid")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.ByteString")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.XmlElement")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.LocalizedText")},
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.QualifiedName")},
		},
	}
	res, err := ch.Read(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading session status"))
		ch.Abort(ctx)
		return
	}
	ch.Close(ctx)
	t.Logf("Results:")
	for i, dv := range res.Results {
		if dv.StatusCode().IsGood() {
			t.Logf("%s: %v", req.NodesToRead[i].NodeID.String(), dv.Value())
		} else {
			t.Error(errors.Wrap(dv.StatusCode(), "Error reading node"))
		}
	}
}

func TestReadIndexRange(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{AttributeID: ua.AttributeIDValue, IndexRange: "0:2", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Double")},
		},
	}
	res, err := ch.Read(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}
	ch.Close(ctx)
	t.Logf("Results:")
	for i, dv := range res.Results {
		t.Logf("%s: %v, %s", req.NodesToRead[i].NodeID.String(), dv.Value(), dv.StatusCode())
	}
}

func TestWriteRange(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, IndexRange: "4:5", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32"), Value: ua.NewDataValueInt32Array([]int32{int32(time.Now().Second()), int32(0)}, 0, time.Time{}, 0, time.Time{}, 0)},
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
	req2 := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{AttributeID: ua.AttributeIDValue, IndexRange: "0:9", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Int32")},
		},
	}
	res2, err := ch.Read(ctx, req2)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}
	t.Logf("%s: %s", req.NodesToWrite[0].NodeID.String(), res.Results[0])
	t.Logf("%s: %v", req2.NodesToRead[0].NodeID.String(), res2.Results[0].Value())
	ch.Close(ctx)
}

func TestReadStringIndexRange(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{AttributeID: ua.AttributeIDValue, IndexRange: "0:2", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.String")},
		},
	}
	res, err := ch.Read(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}
	ch.Close(ctx)
	t.Logf("Results:")
	for i, dv := range res.Results {
		t.Logf("%s: %v, %s", req.NodesToRead[i].NodeID.String(), dv.Value(), dv.StatusCode())
	}
}

func TestWriteStringRange(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, IndexRange: "5", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.String"), Value: ua.NewDataValueString(string("D"), 0, time.Time{}, 0, time.Time{}, 0)},
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
	req2 := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{AttributeID: ua.AttributeIDValue, IndexRange: "0:9", NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.String")},
		},
	}
	res2, err := ch.Read(ctx, req2)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}
	t.Logf("%s: %s", req.NodesToWrite[0].NodeID.String(), res.Results[0])
	t.Logf("%s: %v", req2.NodesToRead[0].NodeID.String(), res2.Results[0].Value())
	ch.Close(ctx)
}

func TestWrite(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Static.Scalar.Double"), Value: ua.NewDataValueDouble(float64(42.0), 0, time.Time{}, 0, time.Time{}, 0)},
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
	t.Logf("%s: %s", req.NodesToWrite[0].NodeID.String(), res.Results[0])
	ch.Close(ctx)
}

func TestBrowse(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{
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
	ch.Close(ctx)
	t.Logf("Browse results of NodeID '%s':", req.NodesToBrowse[0].NodeID)
	for _, r := range res.Results[0].References {
		t.Logf(" + %s, browseName: %s, nodeClass: %s, nodeId: %s", r.DisplayName.Text, r.BrowseName, r.NodeClass, r.NodeID)
	}
}

func TestSubscribe(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
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
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:       &ua.ReadValueID{AttributeID: ua.AttributeIDValue, NodeID: ua.VariableIDServerServerStatusCurrentTime},
				MonitoringMode:      ua.MonitoringModeReporting,
				RequestedParameters: &ua.MonitoringParameters{ClientHandle: 42, QueueSize: 2, DiscardOldest: true, SamplingInterval: 500.0},
			},
		},
	}
	res2, err := ch.CreateMonitoredItems(ctx, req2)
	if err != nil {
		t.Error(errors.Wrap(err, "Error creating item"))
	}
	_ = res2

	pubFunc := func(ctx context.Context, wg *sync.WaitGroup, ch *ua.Client) {
		req := &ua.PublishRequest{
			RequestHeader:                ua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
		}
		for {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			default:
				res, err := ch.Publish(ctx, req)
				if err != nil {
					wg.Done()
					return
				}
				// loop thru all the notifications.
				for _, n := range res.NotificationMessage.NotificationData {
					switch o := n.(type) {
					case *ua.DataChangeNotification:
						for _, z := range o.MonitoredItems {
							if z.ClientHandle == 42 {
								t.Logf(" + CurrentTime: %s", z.Value.Value())
								wg.Done()
								return
							}
						}
					}
				}

				req = &ua.PublishRequest{
					RequestHeader: ua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{
						{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
					},
				}
			}
		}
	}

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go pubFunc(ctx, wg, ch)
	wg.Wait()
	cancelFunc()
	ch.Close(ctx)
}

func TestCallMethod(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())

	req := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID:       ua.ParseNodeID("ns=2;s=Demo.Methods"), // parent node
			MethodID:       ua.ParseNodeID("ns=2;s=Demo.CTT.Methods.MethodIO"),
			InputArguments: []*ua.Variant{ua.NewVariantUInt32(uint32(6)), ua.NewVariantUInt32(uint32(7))}},
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
	ch.Close(ctx)
	t.Logf("  %6d", req.MethodsToCall[0].InputArguments[0].Value())
	t.Logf("+ %6d", req.MethodsToCall[0].InputArguments[1].Value())
	t.Logf("--------")
	t.Logf("  %6d", res.Results[0].OutputArguments[0].Value())
}

func TestTranslate(t *testing.T) {
	ensurePKI(ep)
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())
	req := &ua.TranslateBrowsePathsToNodeIDsRequest{
		BrowsePaths: []*ua.BrowsePath{
			{StartingNode: ua.ParseNodeID("ns=2;s=Demo"), RelativePath: &ua.RelativePath{Elements: []*ua.RelativePathElement{
				{TargetName: ua.ParseQualifiedName("2:Static")},
				{TargetName: ua.ParseQualifiedName("2:Scalar")},
				{TargetName: ua.ParseQualifiedName("2:Float")},
			}}},
		},
	}
	res, err := ch.TranslateBrowsePathsToNodeIDs(ctx, req)
	if err != nil {
		t.Error(errors.Wrap(err, "Error TranslateBrowsePathsToNodeIDs"))
		ch.Abort(ctx)
		return
	}
	ch.Close(ctx)
	t.Logf("Results:")
	for i, r := range res.Results {
		if r.StatusCode.IsGood() {
			t.Logf("%s: %d", req.BrowsePaths[i].StartingNode.String(), len(r.Targets))
			for _, target := range r.Targets {
				t.Logf("  %s: %d", target.TargetID, target.RemainingPathIndex)
			}
		} else {
			t.Logf("code: %s", r.StatusCode)
			t.Logf("%s: %d", req.BrowsePaths[i].StartingNode.String(), len(r.Targets))
			for _, target := range r.Targets {
				t.Logf("  %s: %d", target.TargetID, target.RemainingPathIndex)
			}
			t.Error("Error TranslateBrowsePath")
		}
	}
}

func TestReadHistory(t *testing.T) {
	ensurePKI(ep)
	if testing.Short() {
		t.Skip("skipping long running test")
	}
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		ep,
		ua.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		ua.WithTrustedCertificatesFile("./pki/trusted.pem"),
		ua.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())

	t.Logf("Start logging of data...")
	req := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID:       ua.ParseNodeID("ns=2;s=Demo.History"), // parent node
			MethodID:       ua.ParseNodeID("ns=2;s=Demo.History.StartLogging"),
			InputArguments: []*ua.Variant{}},
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
			HistoryReadDetails: &ua.ReadRawModifiedDetails{
				StartTime:        time.Now().Add(-1 * time.Minute),
				EndTime:          time.Now(),
				NumValuesPerNode: 100,
				ReturnBounds:     false,
			},
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: false,
			NodesToRead: []*ua.HistoryReadValueID{
				{NodeID: ua.ParseNodeID("ns=2;s=Demo.History.DoubleWithHistory"), ContinuationPoint: cp},
			},
		}

		res2, err := ch.HistoryRead(ctx, req2)
		if err != nil {
			t.Error(errors.Wrap(err, "Error reading"))
			ch.Abort(ctx)
			return
		}

		if res2.Results[0].StatusCode.IsGood() {
			if historyData, ok := res2.Results[0].HistoryData.(*ua.HistoryData); ok {
				t.Logf("Found %d value(s) for node '%s':", len(historyData.DataValues), req2.NodesToRead[0].NodeID)
				for _, dv := range historyData.DataValues {
					t.Logf("Read %v, q: %#X, ts: %s", dv.Value(), uint32(dv.StatusCode()), dv.SourceTimestamp())
				}
			} else {
				t.Logf("Error reading values for node '%s'", req2.NodesToRead[0].NodeID)
				t.Error(errors.Wrap(err, "Error reading values"))
				break
			}
		} else {
			t.Logf("Error reading values for node '%s'", req2.NodesToRead[0].NodeID)
			t.Error(errors.Wrap(err, "Error reading values"))
			break
		}

		cp = res2.Results[0].ContinuationPoint
		if cp == "" {
			break
		}
	}
	t.Log("Now read the 1 sec average of the last 10 seconds...")

	req3 := &ua.HistoryReadRequest{
		HistoryReadDetails: &ua.ReadProcessedDetails{
			StartTime:          time.Now().Add(-10 * time.Second),
			EndTime:            time.Now(),
			ProcessingInterval: 1000.0,
			AggregateType:      []ua.NodeID{ua.ObjectIDAggregateFunctionAverage},
		},
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []*ua.HistoryReadValueID{
			{NodeID: ua.ParseNodeID("ns=2;s=Demo.History.DoubleWithHistory")},
		},
	}

	res3, err := ch.HistoryRead(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}

	if res3.Results[0].StatusCode.IsGood() {
		if historyData, ok := res3.Results[0].HistoryData.(*ua.HistoryData); ok {
			t.Logf("Found %d average value(s) for node '%s':", len(historyData.DataValues), req3.NodesToRead[0].NodeID)
			for _, dv := range historyData.DataValues {
				t.Logf("Read %v, q: %#X, ts: %s", dv.Value(), uint32(dv.StatusCode()), dv.SourceTimestamp())
			}
		} else {
			t.Logf("Error reading average  values for node '%s'", req3.NodesToRead[0].NodeID)
			t.Error(errors.Wrap(err, "Error reading average values"))
		}
	} else {
		t.Logf("Error reading average values for node '%s'", req3.NodesToRead[0].NodeID)
		t.Error(errors.Wrap(err, "Error reading average values"))
	}

	t.Logf("Stop logging of data...")
	req4 := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{{
			ObjectID:       ua.ParseNodeID("ns=2;s=Demo.History"), // parent node
			MethodID:       ua.ParseNodeID("ns=2;s=Demo.History.StopLogging"),
			InputArguments: []*ua.Variant{}},
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

func createNewCertificate(appName, certFile, keyFile string) error {

	// Create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// Create a certificate.
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

func ensurePKI(endpointURL string) {

	// make a pki directory, if not exist
	err := os.MkdirAll("./pki", os.ModeDir|0755)
	if err != nil {
		os.Exit(-1)
		return
	}

	// put the server certificate in ./pki/trusted.pem
	res, err := ua.GetEndpoints(context.Background(), &ua.GetEndpointsRequest{EndpointURL: endpointURL})
	if err != nil || len(res.Endpoints) == 0 {
		os.Exit(-1)
		return
	}
	f, err := os.OpenFile("./pki/trusted.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		os.Exit(-1)
		return
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: []byte(res.Endpoints[0].ServerCertificate)})
	if err != nil {
		f.Close()
	}
	f.Close()

	// create a client cert in ./pki/client.crt, if not found
	if _, err := os.Stat("./pki/client.crt"); os.IsNotExist(err) {
		if err := createNewCertificate("test-client", "./pki/client.crt", "./pki/client.key"); err != nil {
			os.Exit(-1)
			return
		}
	}
}
