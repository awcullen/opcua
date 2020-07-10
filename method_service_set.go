// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// Call invokes a list of Methods.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.11.2/
func (ch *Client) Call(ctx context.Context, request *CallRequest) (*CallResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CallResponse), nil
}
