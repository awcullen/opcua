// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// CreateMonitoredItems creates and adds one or more MonitoredItems to a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.2/
func (ch *Client) CreateMonitoredItems(ctx context.Context, request *CreateMonitoredItemsRequest) (*CreateMonitoredItemsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CreateMonitoredItemsResponse), nil
}

// ModifyMonitoredItems modifies MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.3/
func (ch *Client) ModifyMonitoredItems(ctx context.Context, request *ModifyMonitoredItemsRequest) (*ModifyMonitoredItemsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ModifyMonitoredItemsResponse), nil
}

// SetMonitoringMode sets the monitoring mode for one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.4/
func (ch *Client) SetMonitoringMode(ctx context.Context, request *SetMonitoringModeRequest) (*SetMonitoringModeResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*SetMonitoringModeResponse), nil
}

// SetTriggering creates and deletes triggering links for a triggering item.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.5/
func (ch *Client) SetTriggering(ctx context.Context, request *SetTriggeringRequest) (*SetTriggeringResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*SetTriggeringResponse), nil
}

// DeleteMonitoredItems removes one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.6/
func (ch *Client) DeleteMonitoredItems(ctx context.Context, request *DeleteMonitoredItemsRequest) (*DeleteMonitoredItemsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*DeleteMonitoredItemsResponse), nil
}
