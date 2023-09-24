// Copyright 2021 Converter Systems LLC. All rights reserved.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())

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

	go func() {
		// wait for signal (this conflicts with debugger currently)
		log.Println("Press Ctrl-C to exit...")
		waitForSignal()

		log.Println("Closing client abruptly...")
		cancel()
	}()

	for {
		// send request to server. receive response or error
		_, err := ch.Read(ctx, req)
		if err != nil {
			fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
			ch.Abort(ctx)
			return
		}
		time.Sleep(1 * time.Millisecond)
	}

}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
