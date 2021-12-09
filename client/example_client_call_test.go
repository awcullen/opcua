// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

// This example demonstrates calling an method of the server to add two integers and return the sum.
func ExampleClient_Call() {

	ctx := context.Background()

	// open a connection to testserver running locally. Testserver is started if not already running.
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"), // need secure channel to send password
		client.WithUserNameIdentity("root", "secret"),                            // need role of "operator" to call this method
		client.WithInsecureSkipVerify(),                                          // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare call request
	req := &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{
			{
				ObjectID: ua.ParseNodeID("ns=2;s=Demo.Methods"),          // parent of "MethodIO" method
				MethodID: ua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO"), // "MethodIO" method
				InputArguments: []ua.Variant{
					uint32(6),
					uint32(7),
				},
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Call(ctx, req)
	if err != nil {
		fmt.Printf("Error calling method. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	fmt.Printf("Call method result:\n")
	if res.Results[0].StatusCode.IsGood() {
		fmt.Println(res.Results[0].OutputArguments[0].(uint32))
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Call method result:
	// 13
}
