package main

import (
	"context"
	"fmt"
	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
	"time"
)

func main() {

	var testMultiArray = [2][2]bool{
		{false, false},
		{true, true},
	}

	address := "opc.tcp://192.168.30.3:4840"
	nodeId := "ns=3;s=\"PLC\".\"TestMatrix\""

	ctx := context.Background()

	ch, err := client.Dial(
		ctx,
		address,
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	req := &ua.WriteRequest{
		NodesToWrite: []ua.WriteValue{
			{
				NodeID:      ua.ParseNodeID(nodeId),
				AttributeID: ua.AttributeIDValue,
				Value:       ua.NewDataValue(testMultiArray, 0, time.Time{}, 0, time.Time{}, 0),
			},
		},
	}

	res, err := ch.Write(ctx, req)
	if err != nil {
		fmt.Printf("Error writing ServerStatus. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	fmt.Printf("Write attempt: %s\n", res.Results[0])

	//prepare read request
	req2 := &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.ParseNodeID(nodeId),
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res2, err := ch.Read(ctx, req2)
	if err != nil {
		fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	var receivedMatrixArray = [][]bool{}
	receivedMatrixArray = res2.Results[0].Value.([][]bool)
	fmt.Printf("Read atempt: %s\n", receivedMatrixArray)

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

}
