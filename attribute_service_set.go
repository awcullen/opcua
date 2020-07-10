// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// Read returns values of Attributes of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.2/
func (ch *Client) Read(ctx context.Context, request *ReadRequest) (*ReadResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ReadResponse), nil
}

// Write sets values of Attributes of one or more Nodes
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.4/
func (ch *Client) Write(ctx context.Context, request *WriteRequest) (*WriteResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*WriteResponse), nil
}

// HistoryRead returns historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.3/
func (ch *Client) HistoryRead(ctx context.Context, request *HistoryReadRequest) (*HistoryReadResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*HistoryReadResponse), nil
}

// HistoryUpdate sets historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.5/
func (ch *Client) HistoryUpdate(ctx context.Context, request *HistoryUpdateRequest) (*HistoryUpdateResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*HistoryUpdateResponse), nil
}
