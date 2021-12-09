![robot][1]

# opcua - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua)[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Browse, read, write and subscribe to the live data published by the OPC UA servers on your network.

This package supports OPC UA TCP transport protocol with secure channel and binary encoding.  For more information, visit https://reference.opcfoundation.org/v104/.


## Usage
To connect to your OPC UA server, call client.Dial, passing the endpoint URL of the server and various security options. Dial returns a connected client or an error.

With this client, you can call any service of the OPC Unified Architecture, see https://reference.opcfoundation.org/v104/Core/docs/Part4/

For example, to connect to an OPC UA Demo Server, and read the server's status: 

```go
import (
	"context"
	"fmt"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
)

func ExampleClient_ReadMe() {

	ctx := context.Background()

	// open a connection to the on-line OPC UA C++ Demo Server, sponsored by One-Way Automation Inc.
	// See http://www.opcuaserver.com/
	ch, err := client.Dial(
		ctx,
		"opc.tcp://opcuaserver.com:48010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req := &opcua.ReadRequest{
		NodesToRead: []opcua.ReadValueID{
			{
				NodeID:      opcua.VariableIDServerServerStatus,
				AttributeID: opcua.AttributeIDValue,
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
	if serverStatus, ok := res.Results[0].Value.(opcua.ServerStatusDataType); ok {
		fmt.Printf("Server status:\n")
		fmt.Printf("  ProductName: %s\n", serverStatus.BuildInfo.ProductName)
		fmt.Printf("  ManufacturerName: %s\n", serverStatus.BuildInfo.ManufacturerName)
		fmt.Printf("  State: %s\n", serverStatus.State)
	} else {
		fmt.Printf("Error reading ServerStatus.\n")
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