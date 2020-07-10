// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// CreateSubscription creates a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.2/
func (ch *Client) CreateSubscription(ctx context.Context, request *CreateSubscriptionRequest) (*CreateSubscriptionResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*CreateSubscriptionResponse), nil
}

// ModifySubscription modifies a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.3/
func (ch *Client) ModifySubscription(ctx context.Context, request *ModifySubscriptionRequest) (*ModifySubscriptionResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ModifySubscriptionResponse), nil
}

// SetPublishingMode enables sending of Notifications on one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.4/
func (ch *Client) SetPublishingMode(ctx context.Context, request *SetPublishingModeRequest) (*SetPublishingModeResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*SetPublishingModeResponse), nil
}

// Publish requests the Server to return a NotificationMessage or a keep-alive Message.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.5/
func (ch *Client) Publish(ctx context.Context, request *PublishRequest) (*PublishResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*PublishResponse), nil
}

// Republish requests the Server to republish a NotificationMessage from its retransmission queue.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.6/
func (ch *Client) Republish(ctx context.Context, request *RepublishRequest) (*RepublishResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*RepublishResponse), nil
}

// TransferSubscriptions ransfers a Subscription and its MonitoredItems from one Session to another.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.7/
func (ch *Client) TransferSubscriptions(ctx context.Context, request *TransferSubscriptionsRequest) (*TransferSubscriptionsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*TransferSubscriptionsResponse), nil
}

// DeleteSubscriptions deletes one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.8/
func (ch *Client) DeleteSubscriptions(ctx context.Context, request *DeleteSubscriptionsRequest) (*DeleteSubscriptionsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*DeleteSubscriptionsResponse), nil
}
