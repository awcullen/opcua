// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// AddNodes adds one or more Nodes into the AddressSpace hierarchy.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.2/
func (ch *Client) AddNodes(ctx context.Context, request *AddNodesRequest) (*AddNodesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*AddNodesResponse), nil
}

// AddReferences adds one or more References to one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.3/
func (ch *Client) AddReferences(ctx context.Context, request *AddReferencesRequest) (*AddReferencesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*AddReferencesResponse), nil
}

// DeleteNodes deletes one or more Nodes from the AddressSpace.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.4/
func (ch *Client) DeleteNodes(ctx context.Context, request *DeleteNodesRequest) (*DeleteNodesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*DeleteNodesResponse), nil
}

// DeleteReferences deletes one or more References of a Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.5/
func (ch *Client) DeleteReferences(ctx context.Context, request *DeleteReferencesRequest) (*DeleteReferencesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*DeleteReferencesResponse), nil
}
