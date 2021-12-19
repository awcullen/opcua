// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"

	"github.com/awcullen/opcua/ua"
)

// FindServers returns the Servers known to a Server or Discovery Server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func (ch *clientSecureChannel) FindServers(ctx context.Context, request *ua.FindServersRequest) (*ua.FindServersResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.FindServersResponse), nil
}

// GetEndpoints returns the endpoint descriptions supported by the server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/
func (ch *clientSecureChannel) GetEndpoints(ctx context.Context, request *ua.GetEndpointsRequest) (*ua.GetEndpointsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.GetEndpointsResponse), nil
}

// FindServers returns the Servers known to a Server or Discovery Server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func FindServers(ctx context.Context, request *ua.FindServersRequest) (*ua.FindServersResponse, error) {
	ch := newClientSecureChannel(
		ua.ApplicationDescription{
			ApplicationName: ua.LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: ua.ApplicationTypeClient,
		},
		nil,
		nil,
		request.EndpointURL,
		ua.SecurityPolicyURINone,
		ua.MessageSecurityModeNone,
		nil,
		defaultConnectTimeout,
		"",
		false,
		false,
		false,
		defaultTimeoutHint,
		defaultDiagnosticsHint,
		defaultTokenRequestedLifetime,
		false)

	err := ch.Open(ctx)
	if err != nil {
		return nil, err
	}
	res, err := ch.FindServers(ctx, request)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	return res, nil
}

// GetEndpoints returns the endpoint descriptions supported by the server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/
func GetEndpoints(ctx context.Context, request *ua.GetEndpointsRequest) (*ua.GetEndpointsResponse, error) {
	ch := newClientSecureChannel(
		ua.ApplicationDescription{
			ApplicationName: ua.LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: ua.ApplicationTypeClient,
		},
		nil,
		nil,
		request.EndpointURL,
		ua.SecurityPolicyURINone,
		ua.MessageSecurityModeNone,
		nil,
		defaultConnectTimeout,
		"",
		false,
		false,
		false,
		defaultTimeoutHint,
		defaultDiagnosticsHint,
		defaultTokenRequestedLifetime,
		false)

	err := ch.Open(ctx)
	if err != nil {
		return nil, err
	}
	res, err := ch.GetEndpoints(ctx, request)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	return res, nil
}

/// Create a Session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.2/
func (ch *Client) createSession(ctx context.Context, request *ua.CreateSessionRequest) (*ua.CreateSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CreateSessionResponse), nil
}

// Activate a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.3/
func (ch *Client) activateSession(ctx context.Context, request *ua.ActivateSessionRequest) (*ua.ActivateSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.ActivateSessionResponse), nil
}

// Close a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.4/
func (ch *Client) closeSession(ctx context.Context, request *ua.CloseSessionRequest) (*ua.CloseSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CloseSessionResponse), nil
}

// Cancel sends a cancel request.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.5/
func (ch *Client) Cancel(ctx context.Context, request *ua.CancelRequest) (*ua.CancelResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CancelResponse), nil
}

// AddNodes adds one or more Nodes into the AddressSpace hierarchy.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.2/
func (ch *Client) AddNodes(ctx context.Context, request *ua.AddNodesRequest) (*ua.AddNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.AddNodesResponse), nil
}

// AddReferences adds one or more References to one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.3/
func (ch *Client) AddReferences(ctx context.Context, request *ua.AddReferencesRequest) (*ua.AddReferencesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.AddReferencesResponse), nil
}

// DeleteNodes deletes one or more Nodes from the AddressSpace.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.4/
func (ch *Client) DeleteNodes(ctx context.Context, request *ua.DeleteNodesRequest) (*ua.DeleteNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.DeleteNodesResponse), nil
}

// DeleteReferences deletes one or more References of a Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.5/
func (ch *Client) DeleteReferences(ctx context.Context, request *ua.DeleteReferencesRequest) (*ua.DeleteReferencesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.DeleteReferencesResponse), nil
}

// Browse discovers the References of a specified Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.2/
func (ch *Client) Browse(ctx context.Context, request *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.BrowseResponse), nil
}

// BrowseNext requests the next set of Browse responses, when the information is too large to be sent in a single response.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.3/
func (ch *Client) BrowseNext(ctx context.Context, request *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.BrowseNextResponse), nil
}

// TranslateBrowsePathsToNodeIDs translates one or more browse paths to NodeIDs.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.4/
func (ch *Client) TranslateBrowsePathsToNodeIDs(ctx context.Context, request *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.TranslateBrowsePathsToNodeIDsResponse), nil
}

// RegisterNodes registers the Nodes that will be accessed repeatedly (e.g. Write, Call).
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.5/
func (ch *Client) RegisterNodes(ctx context.Context, request *ua.RegisterNodesRequest) (*ua.RegisterNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.RegisterNodesResponse), nil
}

// UnregisterNodes unregisters NodeIDs that have been obtained via the RegisterNodes service.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.6/
func (ch *Client) UnregisterNodes(ctx context.Context, request *ua.UnregisterNodesRequest) (*ua.UnregisterNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.UnregisterNodesResponse), nil
}

// Read returns values of Attributes of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.2/
func (ch *Client) Read(ctx context.Context, request *ua.ReadRequest) (*ua.ReadResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.ReadResponse), nil
}

// Write sets values of Attributes of one or more Nodes
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.4/
func (ch *Client) Write(ctx context.Context, request *ua.WriteRequest) (*ua.WriteResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.WriteResponse), nil
}

// HistoryRead returns historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.3/
func (ch *Client) HistoryRead(ctx context.Context, request *ua.HistoryReadRequest) (*ua.HistoryReadResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.HistoryReadResponse), nil
}

// HistoryUpdate sets historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.5/
func (ch *Client) HistoryUpdate(ctx context.Context, request *ua.HistoryUpdateRequest) (*ua.HistoryUpdateResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.HistoryUpdateResponse), nil
}

// Call invokes a list of Methods.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.11.2/
func (ch *Client) Call(ctx context.Context, request *ua.CallRequest) (*ua.CallResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CallResponse), nil
}

// CreateMonitoredItems creates and adds one or more MonitoredItems to a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.2/
func (ch *Client) CreateMonitoredItems(ctx context.Context, request *ua.CreateMonitoredItemsRequest) (*ua.CreateMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CreateMonitoredItemsResponse), nil
}

// ModifyMonitoredItems modifies MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.3/
func (ch *Client) ModifyMonitoredItems(ctx context.Context, request *ua.ModifyMonitoredItemsRequest) (*ua.ModifyMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.ModifyMonitoredItemsResponse), nil
}

// SetMonitoringMode sets the monitoring mode for one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.4/
func (ch *Client) SetMonitoringMode(ctx context.Context, request *ua.SetMonitoringModeRequest) (*ua.SetMonitoringModeResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.SetMonitoringModeResponse), nil
}

// SetTriggering creates and deletes triggering links for a triggering item.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.5/
func (ch *Client) SetTriggering(ctx context.Context, request *ua.SetTriggeringRequest) (*ua.SetTriggeringResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.SetTriggeringResponse), nil
}

// DeleteMonitoredItems removes one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.6/
func (ch *Client) DeleteMonitoredItems(ctx context.Context, request *ua.DeleteMonitoredItemsRequest) (*ua.DeleteMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.DeleteMonitoredItemsResponse), nil
}

// CreateSubscription creates a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.2/
func (ch *Client) CreateSubscription(ctx context.Context, request *ua.CreateSubscriptionRequest) (*ua.CreateSubscriptionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.CreateSubscriptionResponse), nil
}

// ModifySubscription modifies a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.3/
func (ch *Client) ModifySubscription(ctx context.Context, request *ua.ModifySubscriptionRequest) (*ua.ModifySubscriptionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.ModifySubscriptionResponse), nil
}

// SetPublishingMode enables sending of Notifications on one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.4/
func (ch *Client) SetPublishingMode(ctx context.Context, request *ua.SetPublishingModeRequest) (*ua.SetPublishingModeResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.SetPublishingModeResponse), nil
}

// Publish requests the Server to return a NotificationMessage or a keep-alive Message.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.5/
func (ch *Client) Publish(ctx context.Context, request *ua.PublishRequest) (*ua.PublishResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.PublishResponse), nil
}

// Republish requests the Server to republish a NotificationMessage from its retransmission queue.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.6/
func (ch *Client) Republish(ctx context.Context, request *ua.RepublishRequest) (*ua.RepublishResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.RepublishResponse), nil
}

// TransferSubscriptions ransfers a Subscription and its MonitoredItems from one Session to another.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.7/
func (ch *Client) TransferSubscriptions(ctx context.Context, request *ua.TransferSubscriptionsRequest) (*ua.TransferSubscriptionsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.TransferSubscriptionsResponse), nil
}

// DeleteSubscriptions deletes one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.8/
func (ch *Client) DeleteSubscriptions(ctx context.Context, request *ua.DeleteSubscriptionsRequest) (*ua.DeleteSubscriptionsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*ua.DeleteSubscriptionsResponse), nil
}
