package opcua_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
	"github.com/pkg/errors"
)

func TestDeserializeBaseEvent(t *testing.T) {
	f := []opcua.Variant{
		opcua.ByteString("foo"),
		opcua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		opcua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
	}
	e := opcua.NewBaseEvent(f)
	t.Logf("%+v", e)
}

func TestDeserializeCondition(t *testing.T) {
	f := []opcua.Variant{
		opcua.ByteString("foo"),
		opcua.NewNodeIDString(1, "bar"),
		"source",
		time.Now().UTC(),
		opcua.NewLocalizedText("Temperature is high.", "en"),
		uint16(255),
		opcua.NewNodeIDNumeric(1, 45),
		"ConditionName",
		nil,
		true,
	}
	e := opcua.NewCondition(f)
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
	req := &opcua.CreateSubscriptionRequest{
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
	req2 := &opcua.CreateMonitoredItemsRequest{
		SubscriptionID:     res.SubscriptionID,
		TimestampsToReturn: opcua.TimestampsToReturnBoth,
		ItemsToCreate: []opcua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  opcua.ReadValueID{AttributeID: opcua.AttributeIDEventNotifier, NodeID: opcua.ObjectIDServer},
				MonitoringMode: opcua.MonitoringModeReporting,
				RequestedParameters: opcua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					Filter: opcua.EventFilter{SelectClauses: opcua.BaseEventSelectClauses},
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
		req := &opcua.PublishRequest{
			RequestHeader:                opcua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{},
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
					case opcua.EventNotificationList:
						for _, z := range body.Events {
							if z.ClientHandle == 42 {
								e := opcua.NewBaseEvent(z.EventFields)
								t.Logf("%+v", e)
								wg.Done()
								return
							}
						}
					}
				}

				req = &opcua.PublishRequest{
					RequestHeader: opcua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{
						{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
					},
				}
			}
		}
	}()

	req3 := &opcua.WriteRequest{
		NodesToWrite: []opcua.WriteValue{
			{AttributeID: opcua.AttributeIDValue, NodeID: opcua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: opcua.DataValue{true, 0, time.Time{}, 0, time.Time{}, 0}},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &opcua.WriteRequest{
		NodesToWrite: []opcua.WriteValue{
			{AttributeID: opcua.AttributeIDValue, NodeID: opcua.ParseNodeID("ns=2;s=Demo.Events.Trigger_BaseEvent"), Value: opcua.DataValue{false, 0, time.Time{}, 0, time.Time{}, 0}},
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
	req := &opcua.CreateSubscriptionRequest{
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
	req2 := &opcua.CreateMonitoredItemsRequest{
		SubscriptionID:     res.SubscriptionID,
		TimestampsToReturn: opcua.TimestampsToReturnBoth,
		ItemsToCreate: []opcua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  opcua.ReadValueID{AttributeID: opcua.AttributeIDEventNotifier, NodeID: opcua.ObjectIDServer},
				MonitoringMode: opcua.MonitoringModeReporting,
				RequestedParameters: opcua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1000, DiscardOldest: true, SamplingInterval: 0.0,
					Filter: opcua.EventFilter{SelectClauses: opcua.AlarmConditionSelectClauses},
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
		req := &opcua.PublishRequest{
			RequestHeader:                opcua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{},
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
					case opcua.EventNotificationList:
						for _, z := range body.Events {
							if z.ClientHandle == 42 {
								e := opcua.NewAlarmCondition(z.EventFields)
								t.Logf("%+v", e)
								wg.Done()
								return
							}
						}
					}
				}

				req = &opcua.PublishRequest{
					RequestHeader: opcua.RequestHeader{TimeoutHint: 60000},
					SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{
						{SequenceNumber: res.NotificationMessage.SequenceNumber, SubscriptionID: res.SubscriptionID},
					},
				}
			}
		}
	}()

	req3 := &opcua.WriteRequest{
		NodesToWrite: []opcua.WriteValue{
			{AttributeID: opcua.AttributeIDValue, NodeID: opcua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: opcua.DataValue{true, 0, time.Time{}, 0, time.Time{}, 0}},
		},
	}
	_, err = ch.Write(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error writing"))
		ch.Abort(ctx)
		return
	}
	req4 := &opcua.WriteRequest{
		NodesToWrite: []opcua.WriteValue{
			{AttributeID: opcua.AttributeIDValue, NodeID: opcua.ParseNodeID("ns=2;s=AlarmsNoNodes.OffNormalAlarmTrigger"), Value: opcua.DataValue{false, 0, time.Time{}, 0, time.Time{}, 0}},
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
