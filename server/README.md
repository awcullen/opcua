# server - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua/server) [![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Publish data to the OPC UA clients in your network.

With this package, you can create a server of the OPC Unified Architecture, see https://reference.opcfoundation.org/v104/Core/docs/Part4/

## Usage
To create your OPC UA server, call server.New(). Specify the server's description, certificate, private key, endpoint URL, and various options. 

Create a namespace, and add nodes of types Object, Variable, Method and DataType.

Run the server by calling ListenAndServer().

To stop the server, call Close().

```go
package main

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

func main() {

	// create directory with certificate and key, if not found.
	if err := ensurePKI(); err != nil {
		log.Println("Error creating PKI.")
		return
	}

    // create the endpoint url from hostname and port
	host, _ := os.Hostname()
	port := 46010
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)

	// create server
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("testserver@%s", host),
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  "0.3.0",
			}),
		server.WithAnonymousIdentity(true),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithServerDiagnostics(true),
	)
	if err != nil {
		os.Exit(1)
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer([]byte(nodeset)); err != nil {
		os.Exit(2)
	}

	go func() {
		// wait for signal
		log.Println("Press Ctrl-C to exit...")
		waitForSignal()

		log.Println("Stopping server...")
		srv.Close()
	}()

	// start server
	log.Printf("Starting server '%s' at '%s'\n", srv.LocalDescription().ApplicationName.Text, srv.EndpointURL())
	if err := srv.ListenAndServe(); err != ua.BadServerHalted {
		log.Println(errors.Wrap(err, "Error opening server"))
	}
}


```
