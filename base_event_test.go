package opcua_test

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	ua "github.com/awcullen/opcua"
	"github.com/pkg/errors"
)

func TestDeserializeBaseEvent(t *testing.T) {
	e := &ua.BaseEvent{}
	f := []*ua.Variant{
		ua.NewVariantByteArray([]byte("foo")),
		ua.NewVariantNodeID(ua.NewNodeIDString(1, "bar")),
		ua.NewVariantString("source"),
		ua.NewVariantDateTime(time.Now().UTC()),
		ua.NewVariantLocalizedText(ua.NewLocalizedText("Temperature is high.", "en")),
		ua.NewVariantUInt16(255),
	}
	err := ua.DeserializeEvent(e, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", e)
}

func TestDeserializeCondition(t *testing.T) {
	e := &ua.Condition{}
	f := []*ua.Variant{
		ua.NewVariantByteArray([]byte("foo")),
		ua.NewVariantNodeID(ua.NewNodeIDString(1, "bar")),
		ua.NewVariantString("source"),
		ua.NewVariantDateTime(time.Now().UTC()),
		ua.NewVariantLocalizedText(ua.NewLocalizedText("Temperature is high.", "en")),
		ua.NewVariantUInt16(255),
		ua.NewVariantNodeID(ua.NewNodeIDNumeric(1, 45)),
		ua.NewVariantString("ConditionName"),
		ua.NewVariantNodeID(ua.NilNodeID),
		ua.NewVariantBoolean(true),
	}
	err := ua.DeserializeEvent(e, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", e)
}

// requires UnifiedAutomation UaCPPServer
func TestSubscribeBaseEvent(t *testing.T) {
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		"opc.tcp://127.0.0.1:48010",
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
				ItemToMonitor:  &ua.ReadValueID{AttributeID: ua.AttributeIDEventNotifier, NodeID: ua.ObjectIDServer},
				MonitoringMode: ua.MonitoringModeReporting,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					Filter: &ua.EventFilter{SelectClauses: ua.GetSelectClauses(reflect.TypeOf(ua.BaseEvent{}))},
				},
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
					case *ua.EventNotificationList:
						for _, z := range o.Events {
							if z.ClientHandle == 42 {
								e := &ua.BaseEvent{}
								ua.DeserializeEvent(e, z.EventFields)
								t.Logf("%+v", e)
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

	ctx, cancelFunc := context.WithTimeout(ctx, 60*time.Second)
	defer cancelFunc()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go pubFunc(ctx, wg, ch)

	req3 := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: ua.NewDataValueBoolean(true, 0, time.Time{}, 0, time.Time{}, 0)},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: ua.NewDataValueBoolean(false, 0, time.Time{}, 0, time.Time{}, 0)},
		},
	}
	_, err = ch.Write(ctx, req4)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}

	wg.Wait()

	ch.Close(ctx)
}

// requires UnifiedAutomation UaCPPServer
func TestSubscribeAlarm(t *testing.T) {
	ctx := context.Background()
	ch, err := ua.NewClient(
		ctx,
		"opc.tcp://127.0.0.1:48010",
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
				ItemToMonitor:  &ua.ReadValueID{AttributeID: ua.AttributeIDEventNotifier, NodeID: ua.ObjectIDServer},
				MonitoringMode: ua.MonitoringModeReporting,
				RequestedParameters: &ua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					// use
					Filter: &ua.EventFilter{SelectClauses: ua.GetSelectClauses(reflect.TypeOf(ua.AlarmCondition{}))},
				},
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
					case *ua.EventNotificationList:
						for _, z := range o.Events {
							if z.ClientHandle == 42 {
								e := &ua.AlarmCondition{}
								ua.DeserializeEvent(e, z.EventFields)
								t.Logf("%+v", e)
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

	ctx, cancelFunc := context.WithTimeout(ctx, 60*time.Second)
	defer cancelFunc()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go pubFunc(ctx, wg, ch)

	req3 := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: ua.NewDataValueBoolean(true, 0, time.Time{}, 0, time.Time{}, 0)},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: ua.NewDataValueBoolean(false, 0, time.Time{}, 0, time.Time{}, 0)},
		},
	}
	_, err = ch.Write(ctx, req4)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}

	wg.Wait()

	ch.Close(ctx)
}
