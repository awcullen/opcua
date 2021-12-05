// Copyright 2021 Converter Systems LLC. All rights reserved.

package client_test

import (
	"context"
	"fmt"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
)

// This example demonstrates browsing the top-level 'Objects' folder of the server. 
func ExampleClient_Browse() {

	ctx := context.Background()

	// open a connection to the testserver
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:46010",
		client.WithInsecureSkipVerify(), // skips verification of server certificate
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return
	}

	// prepare browse request
	req := &opcua.BrowseRequest{
		View: opcua.ViewDescription{},
		NodesToBrowse: []opcua.BrowseDescription{
			{
				NodeID:          opcua.ParseNodeID("i=85"), // Objects folder
				BrowseDirection: opcua.BrowseDirectionForward,
				ReferenceTypeID: opcua.ReferenceTypeIDHierarchicalReferences,
				IncludeSubtypes: true,
				ResultMask:      uint32(opcua.BrowseResultMaskTargetInfo),
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Browse(ctx, req)
	if err != nil {
		fmt.Printf("Error browsing Objects folder. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	// print results
	fmt.Printf("Browse results of NodeID '%s':\n", req.NodesToBrowse[0].NodeID)
	for _, r := range res.Results[0].References {
		fmt.Printf(" + %s, browseName: %s, nodeClass: %s, nodeId: %s\n", r.DisplayName.Text, r.BrowseName, r.NodeClass, r.NodeID)
	}

	// close connection
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return
	}

	// Output:
	// Browse results of NodeID 'i=85':
	//  + Server, browseName: 0:Server, nodeClass: Object, nodeId: i=2253
	//  + Demo, browseName: 2:Demo, nodeClass: Object, nodeId: ns=2;s=Demo
}
