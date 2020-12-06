// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua_test

import (
	"context"
	"fmt"

	ua "github.com/awcullen/opcua"
)

func ExampleClient_Call() {

	ctx := context.Background()

	// open a connection to the C++ SDK OPC UA Demo Server, available for free from Unified Automation GmbH.
	ch, err := ua.NewClient(
		ctx,
		"opc.tcp://localhost:48010",
		ua.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare call request
	req := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: ua.ParseNodeID("ns=2;s=Demo.Method"),          // parent of "Multiply" method
				MethodID: ua.ParseNodeID("ns=2;s=Demo.Method.Multiply"), // "Multiply" method
				InputArguments: []*ua.Variant{
					ua.NewVariantDouble(6.0),
					ua.NewVariantDouble(7.0),
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
		fmt.Println(res.Results[0].OutputArguments[0].Value().(float64))
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Call method result:
	// 42
}
