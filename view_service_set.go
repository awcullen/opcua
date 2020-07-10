// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// Browse discovers the References of a specified Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.2/
func (ch *Client) Browse(ctx context.Context, request *BrowseRequest) (*BrowseResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*BrowseResponse), nil
}

// BrowseNext requests the next set of Browse responses, when the information is too large to be sent in a single response.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.3/
func (ch *Client) BrowseNext(ctx context.Context, request *BrowseNextRequest) (*BrowseNextResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*BrowseNextResponse), nil
}

// TranslateBrowsePathsToNodeIDs translates one or more browse paths to NodeIDs.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.4/
func (ch *Client) TranslateBrowsePathsToNodeIDs(ctx context.Context, request *TranslateBrowsePathsToNodeIDsRequest) (*TranslateBrowsePathsToNodeIDsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*TranslateBrowsePathsToNodeIDsResponse), nil
}

// RegisterNodes registers the Nodes that will be accessed repeatedly (e.g. Write, Call).
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.5/
func (ch *Client) RegisterNodes(ctx context.Context, request *RegisterNodesRequest) (*RegisterNodesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*RegisterNodesResponse), nil
}

// UnregisterNodes unregisters NodeIDs that have been obtained via the RegisterNodes service.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.6/
func (ch *Client) UnregisterNodes(ctx context.Context, request *UnregisterNodesRequest) (*UnregisterNodesResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*UnregisterNodesResponse), nil
}
