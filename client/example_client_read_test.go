// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

// This example demonstrates reading the 'ServerStatus' variable.
func ExampleClient_Read() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req := &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.VariableIDServerServerStatus,
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if serverStatus, ok := res.Results[0].Value.(ua.ServerStatusDataType); ok {
		fmt.Printf("Server status:\n")
		fmt.Printf("  ProductName: %s\n", serverStatus.BuildInfo.ProductName)
		fmt.Printf("  ManufacturerName: %s\n", serverStatus.BuildInfo.ManufacturerName)
		fmt.Printf("  State: %s\n", serverStatus.State)
	} else {
		fmt.Println("Error decoding ServerStatus.")
	}


	// Output:
	// Server status:
	//   ProductName: testserver
	//   ManufacturerName: awcullen
	//   State: Running
}

// This example demonstrates reading the 'CustomStruct' variable.
func ExampleClient_Read_customstruct() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req := &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.ParseNodeID("ns=2;i=14"),
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading CustomStruct. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if custom, ok := res.Results[0].Value.(CustomStruct); ok {
		fmt.Printf("CustomStruct:\n")
		fmt.Printf("  W1: %d\n", custom.W1)
		fmt.Printf("  W2: %d\n", custom.W2)
	} else {
		fmt.Println("Error decoding CustomStruct.")
	}
	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// CustomStruct:
	//   W1: 1
	//   W2: 2
}
