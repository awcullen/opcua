// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua_test

import (
	"context"
	"fmt"
	"time"

	ua "github.com/awcullen/opcua"
)

func ExampleClient_Publish() {

	ctx := context.Background()

	// open a connection to the OPC UA server at url "opc.tcp://opcua.rocks:4840".
	ch, err := ua.NewClient(
		ctx,
		"opc.tcp://opcua.rocks:4840",
		ua.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare create subscription request
	req := &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: 1000.0,
		RequestedMaxKeepAliveCount:  30,
		RequestedLifetimeCount:      30 * 3,
		PublishingEnabled:           true,
	}

	// send request to server. receive response or error
	res, err := ch.CreateSubscription(ctx, req)
	if err != nil {
		fmt.Printf("Error creating subscription. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// prepare create monitored items request
	req2 := &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     res.SubscriptionID,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  &ua.ReadValueID{AttributeID: ua.AttributeIDValue, NodeID: ua.VariableIDServerServerStatusCurrentTime},
				MonitoringMode: ua.MonitoringModeReporting,
				// specify a unique ClientHandle. The ClientHandle is returned in the PublishResponse
				RequestedParameters: &ua.MonitoringParameters{ClientHandle: 42, QueueSize: 2, DiscardOldest: true, SamplingInterval: 1000.0},
			},
		},
	}

	// send request to server. receive response or error
	_, err = ch.CreateMonitoredItems(ctx, req2)
	if err != nil {
		fmt.Printf("Error creating item. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// prepare an initial publish request
	req3 := &ua.PublishRequest{
		RequestHeader:                ua.RequestHeader{TimeoutHint: 60000},
		SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
	}

	// send publish requests to the server for 5 sec
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)

	for {
		// send the publish request to the server. returns response or error
		res3, err := ch.Publish(ctx, req3)
		if err != nil {
			break
		}
		// loop thru all the notifications in the response.
		for _, data := range res3.NotificationMessage.NotificationData {
			switch notification := data.(type) {
			case *ua.DataChangeNotification:
				// the data change notification will contain a slice of monitored item notifications.
				for _, item := range notification.MonitoredItems {
					// each monitored item notification will contain a clientHandle and dataValue.
					if item.ClientHandle == 42 {
						fmt.Println("<the current utc time here>" /* item.Value.Value() */)
					}
				}
			}
		}
		// prepare another publish request
		req3 = &ua.PublishRequest{
			RequestHeader: ua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{
				{SequenceNumber: res3.NotificationMessage.SequenceNumber, SubscriptionID: res3.SubscriptionID},
			},
		}
	}

	// wait for publish to complete, then clean up timer.
	cancel()

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// <the current utc time here>
	// <the current utc time here>
	// <the current utc time here>
	// <the current utc time here>
	// <the current utc time here>
}
