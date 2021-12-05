// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
)

// This example demonstrates calling an method of the server to add two integers and return the sum. 
func ExampleClient_Call() {

	ctx := context.Background()

	// open a connection to the testserver
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
	req := &opcua.CallRequest{
		MethodsToCall: []opcua.CallMethodRequest{
			{
				ObjectID: opcua.ParseNodeID("ns=2;s=Demo.Methods"),          // parent of "MethodIO" method
				MethodID: opcua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO"), // "MethodIO" method
				InputArguments: []opcua.Variant{
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
