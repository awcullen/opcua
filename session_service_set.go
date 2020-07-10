// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

/// Create a Session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.2/
func (ch *Client) createSession(ctx context.Context, request *CreateSessionRequest) (*CreateSessionResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CreateSessionResponse), nil
}

// Activate a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.3/
func (ch *Client) activateSession(ctx context.Context, request *ActivateSessionRequest) (*ActivateSessionResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ActivateSessionResponse), nil
}

// Close a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.4/
func (ch *Client) closeSession(ctx context.Context, request *CloseSessionRequest) (*CloseSessionResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CloseSessionResponse), nil
}

// Cancel sends a cancel request.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.5/
func (ch *Client) Cancel(ctx context.Context, request *CancelRequest) (*CancelResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CancelResponse), nil
}
