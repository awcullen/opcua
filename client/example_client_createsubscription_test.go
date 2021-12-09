// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
)

// This example demonstrates subscribing to the server's 'CurrentTime' variable and receiving data changes.
func ExampleClient_CreateSubscription() {

	ctx := context.Background()

	// open a connection to the testserver
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare create subscription request
	req := &opcua.CreateSubscriptionRequest{
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
	req2 := &opcua.CreateMonitoredItemsRequest{
		SubscriptionID:     res.SubscriptionID,
		TimestampsToReturn: opcua.TimestampsToReturnBoth,
		ItemsToCreate: []opcua.MonitoredItemCreateRequest{
			{
				ItemToMonitor:  opcua.ReadValueID{
					NodeID: opcua.VariableIDServerServerStatusCurrentTime, 
					AttributeID: opcua.AttributeIDValue,
				},
				MonitoringMode: opcua.MonitoringModeReporting,
				// specify a unique ClientHandle. The ClientHandle is returned in the PublishResponse
				RequestedParameters: opcua.MonitoringParameters{
					ClientHandle: 42, QueueSize: 1, DiscardOldest: true, SamplingInterval: 1000.0},
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
	req3 := &opcua.PublishRequest{
		RequestHeader:                opcua.RequestHeader{TimeoutHint: 60000},
		SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{},
	}

	// loop until 3 data changes received.
	numChanges := 0
	for numChanges < 3 {
		// send publish request to the server.
		res3, err := ch.Publish(ctx, req3)
		if err != nil {
			break
		}
		// loop thru all the notifications in the response.
		for _, data := range res3.NotificationMessage.NotificationData {
			switch body := data.(type) {
			case opcua.DataChangeNotification:
				// the data change notification contains a slice of monitored item notifications.
				for _, item := range body.MonitoredItems {
					// each monitored item notification contains a clientHandle and dataValue.
					if item.ClientHandle == 42 {
						fmt.Println("<the current utc time here>" /* item.Value.Value */)
						numChanges++
					}
				}
			}
		}
		// prepare another publish request
		req3 = &opcua.PublishRequest{
			RequestHeader: opcua.RequestHeader{TimeoutHint: 60000},
			SubscriptionAcknowledgements: []opcua.SubscriptionAcknowledgement{
				{SequenceNumber: res3.NotificationMessage.SequenceNumber, SubscriptionID: res3.SubscriptionID},
			},
		}
	}

	// success after receiving 3 data changes.

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
}
