// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua_test

import (
	"context"
	"fmt"

	ua "github.com/awcullen/opcua"
)

func ExampleClient_Call() {

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

	// prepare call request
	req := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{
			{
				ObjectID: ua.ParseNodeID("i=85"),         // Objects folder
				MethodID: ua.ParseNodeID("ns=1;i=62541"), // "Hello World" method
				InputArguments: []*ua.Variant{
					ua.NewVariantString("World!"),
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
		fmt.Println(res.Results[0].OutputArguments[0].Value().(string))
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Call method result:
	// Hello World!
}
