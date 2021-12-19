# client - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua/client) [![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Browse, read, write and subscribe to data published by the OPC UA servers in your network.

With this package, you can call any service of the OPC Unified Architecture, see https://reference.opcfoundation.org/v104/Core/docs/Part4/

## Usage
To connect to your OPC UA server, call client.Dial, passing the endpoint URL of the server and various security options. Dial returns a connected client or an error.

For example, to connect to an OPC UA Demo Server, and read the server's status: 

```go
package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

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


```
