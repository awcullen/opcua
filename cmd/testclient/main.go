// Copyright 2021 Converter Systems LLC. All rights reserved.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		fmt.Println("Press Ctrl-C to exit...")
		waitForSignal()
		fmt.Println("Stopping client...")
		cancel()
	}()

	var ch *client.Client
	var err error
	var req *ua.ReadRequest

	// open a connection to testserver running locally.
	ch, err = client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		client.WithUserNameIdentity("root", "secret"),
		client.WithInsecureSkipVerify(), // skips verification of server certificate
		client.WithTokenLifetime(20000),
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare read request
	req = &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.VariableIDServerServerStatus,
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	for i := 0; i < 1000; i++ {
		// send request to server. receive response or error
		_, err = ch.Read(ctx, req)
		if err != nil {
			fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
			ch.Abort(ctx)
			return
		}
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		fmt.Printf("Error closing client. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
