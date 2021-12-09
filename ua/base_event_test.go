package ua_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
)

func TestDeserializeBaseEvent(t *testing.T) {
	f := []ua.Variant{
		ua.ByteString("foo"),
		ua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		ua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
	}
	e := ua.NewBaseEvent(f)
	t.Logf("%+v", e)
}

func TestDeserializeCondition(t *testing.T) {
	f := []ua.Variant{
		ua.ByteString("foo"),
		ua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		ua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
		ua.NewNodeIDNumeric(1, 45),
		"ConditionName",
		nil,
		true,
	}
	e := ua.NewCondition(f)
	t.Logf("%+v", e)
}

// requires UnifiedAutomation UaCPPServer
func TestSubscribeBaseEvent(t *testing.T) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelFunc()

	// open a connection to the C++ SDK OPC UA Demo Server, available for free from Unified Automation GmbH.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://127.0.0.1:48010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
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
		ItemsToCreate: []ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  ua.ReadValueID{AttributeID: ua.AttributeIDEventNotifier, NodeID: ua.ObjectIDServer},
				MonitoringMode: ua.MonitoringModeReporting,
				RequestedParameters: ua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					Filter: ua.EventFilter{SelectClauses: ua.BaseEventSelectClauses},
				},
			},
		},
	}
	res2, err := ch.CreateMonitoredItems(ctx, req2)
	if err != nil {
		t.Error(errors.Wrap(err, "Error creating item"))
	}
	_ = res2

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		req := &ua.PublishRequest{
			RequestHeader:                ua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{},
		}
		for {
			select {
			case <-ctx.Done():
				t.Error(errors.Wrap(err, "Error timeout"))
				wg.Done()
				return
			default:
				res, err := ch.Publish(ctx, req)
				if err != nil {
					wg.Done()
					return
				}
				// loop thru all the notifications.
				for _, data := range res.NotificationMessage.NotificationData {
					switch body := data.(type) {
					case ua.EventNotificationList:
						for _, z := range body.Events {
							if z.ClientHandle == 42 {
								e := ua.NewBaseEvent(z.EventFields)
								t.Logf("%+v", e)
								wg.Done()
								return
							}
						}
					}
				}

				req = &ua.PublishRequest{
					RequestHeader: ua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{
						{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
					},
				}
			}
		}
	}()

	req3 := &ua.WriteRequest{
		NodesToWrite: []ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: ua.DataValue{true, 0, time.Time{}, 0, time.Time{}, 0}},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &ua.WriteRequest{
		NodesToWrite: []ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: ua.DataValue{false, 0, time.Time{}, 0, time.Time{}, 0}},
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
	ctx, cancelFunc := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelFunc()

	// open a connection to the C++ SDK OPC UA Demo Server, available for free from Unified Automation GmbH.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://127.0.0.1:48010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
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
		ItemsToCreate: []ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  ua.ReadValueID{AttributeID: ua.AttributeIDEventNotifier, NodeID: ua.ObjectIDServer},
				MonitoringMode: ua.MonitoringModeReporting,
				RequestedParameters: ua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					Filter: ua.EventFilter{SelectClauses: ua.AlarmConditionSelectClauses},
				},
			},
		},
	}
	res2, err := ch.CreateMonitoredItems(ctx, req2)
	if err != nil {
		t.Error(errors.Wrap(err, "Error creating item"))
	}
	_ = res2

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		req := &ua.PublishRequest{
			RequestHeader:                ua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{},
		}
		for {
			select {
			case <-ctx.Done():
				t.Error(errors.Wrap(err, "Error timeout"))
				wg.Done()
				return
			default:
				res, err := ch.Publish(ctx, req)
				if err != nil {
					wg.Done()
					return
				}
				// loop thru all the notifications.
				for _, data := range res.NotificationMessage.NotificationData {
					switch body := data.(type) {
					case ua.EventNotificationList:
						for _, z := range body.Events {
							if z.ClientHandle == 42 {
								e := ua.NewAlarmCondition(z.EventFields)
								t.Logf("%+v", e)
								wg.Done()
								return
							}
						}
					}
				}

				req = &ua.PublishRequest{
					RequestHeader: ua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{
						{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
					},
				}
			}
		}
	}()

	req3 := &ua.WriteRequest{
		NodesToWrite: []ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: ua.DataValue{true, 0, time.Time{}, 0, time.Time{}, 0}},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &ua.WriteRequest{
		NodesToWrite: []ua.WriteValue{
			{AttributeID: ua.AttributeIDValue, NodeID: ua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: ua.DataValue{false, 0, time.Time{}, 0, time.Time{}, 0}},
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
