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

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
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

// This example demonstrates reading an multidimensional array variable.
func ExampleClient_Read_array() {

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
				NodeID:      ua.ParseNodeID("ns=2;s=Demo.Static.Arrays.Matrix"),
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading value. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if val, ok := res.Results[0].Value.([][][]int32); ok {
		fmt.Println(val)
	} else {
		fmt.Println("Error decoding [][][]int32.")
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// [[[0 1 2] [3 4 5] [6 7 8] [9 10 11]] [[12 13 14] [15 16 17] [18 19 20] [21 22 23]]]
}

// This example demonstrates reading the 'Test2D' variable.
func ExampleClient_Read_array2D() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://10.0.0.4:4840",
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
				NodeID:      ua.ParseNodeID(`ns=3;s="Global"."Test2D"`),
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading value. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if val, ok := res.Results[0].Value.([][]int16); ok {
		fmt.Println(val)
	} else {
		fmt.Println("Error decoding value.")
	}
	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// [[0 0 0] [0 0 0] [0 0 0] [0 0 0]]
}

// This example demonstrates reading the 'StructA' variable.
func ExampleClient_Read_structA() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://10.0.0.4:4840",
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
				NodeID:      ua.ParseNodeID(`ns=3;s="Global"."TestStructA"`),
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading value. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	if val, ok := res.Results[0].Value.(StructA); ok {
		fmt.Printf("StructA:\n")
		fmt.Printf("  A: %v\n", val.A)
	} else {
		fmt.Println("Error decoding value.")
	}
	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// StructA:
	//   A: [[0 0] [0 0]]
}
