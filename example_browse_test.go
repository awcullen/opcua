// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua_test

import (
	"context"
	"fmt"

	ua "github.com/awcullen/opcua"
)

func ExampleClient_Browse() {

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

	// prepare browse request
	req := &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{
			{
				NodeID:          ua.ParseNodeID("i=85"), // Objects folder
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ua.ReferenceTypeIDHierarchicalReferences,
				IncludeSubtypes: true,
				ResultMask:      uint32(ua.BrowseResultMaskTargetInfo),
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
	//  + Event Object (2s), browseName: 1:Event Object, nodeClass: Object, nodeId: ns=1;i=42
	//  + Hello World, browseName: 1:hello world, nodeClass: Method, nodeId: ns=1;i=62541
}
