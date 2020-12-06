![robot][1]

# opcua - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua)[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Browse, read, write and subscribe to the live data published by the OPC UA servers on your network.

This package supports OPC UA TCP transport protocol with secure channel and binary encoding.  For more information, visit https://reference.opcfoundation.org/v104/.


## Usage
To connect to your OPC UA server, call NewClient, passing the endpoint URL of the server and various security options. NewClient returns a connected client or an error.

With the client, you can call any service of the OPC Unified Architecture, see https://reference.opcfoundation.org/v104/Core/docs/Part4/

For example, to connect to an OPC UA Demo Server, and read the server's status: 

```go
import (
	"context"
	"fmt"

	ua "github.com/awcullen/opcua"
)

func ExampleClient_Read() {

	ctx := context.Background()

	// open a connection to the C++ SDK OPC UA Demo Server, available for free from Unified Automation GmbH. See https://www.unified-automation.com/downloads.html
	
	ch, err := ua.NewClient(
		ctx,
		"opc.tcp://localhost:48010",
		ua.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
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
	if serverStatus, ok := res.Results[0].Value().(*ua.ServerStatusDataType); ok {
		fmt.Printf("Server status:\n")
		fmt.Printf("  ProductName: %s\n", serverStatus.BuildInfo.ProductName)
		fmt.Printf("  ManufacturerName: %s\n", serverStatus.BuildInfo.ManufacturerName)
		fmt.Printf("  State: %s\n", serverStatus.State)
	} else {
		fmt.Printf("Error reading ServerStatus. %s\n", res.Results[0].StatusCode())
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Server status:
	//   ProductName: C++ SDK OPC UA Demo Server
	//   ManufacturerName: Unified Automation GmbH
	//   State: Running
}

```
 [1]: robot6.jpg