// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
	"crypto/tls"

	"github.com/awcullen/opcua"
)

// FindServers returns the Servers known to a Server or Discovery Server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func (ch *clientSecureChannel) FindServers(ctx context.Context, request *opcua.FindServersRequest) (*opcua.FindServersResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.FindServersResponse), nil
}

// GetEndpoints returns the endpoint descriptions supported by the server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/
func (ch *clientSecureChannel) GetEndpoints(ctx context.Context, request *opcua.GetEndpointsRequest) (*opcua.GetEndpointsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.GetEndpointsResponse), nil
}

// FindServers returns the Servers known to a Server or Discovery Server
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func FindServers(ctx context.Context, request *opcua.FindServersRequest) (*opcua.FindServersResponse, error) {
	ch := newClientSecureChannel(
		opcua.ApplicationDescription{
			ApplicationName: opcua.LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: opcua.ApplicationTypeClient,
		},
		nil,
		nil,
		request.EndpointURL,
		opcua.SecurityPolicyURINone,
		opcua.MessageSecurityModeNone,
		nil,
		defaultConnectTimeout,
		tls.Certificate{},
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
// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/
func GetEndpoints(ctx context.Context, request *opcua.GetEndpointsRequest) (*opcua.GetEndpointsResponse, error) {
	ch := newClientSecureChannel(
		opcua.ApplicationDescription{
			ApplicationName: opcua.LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: opcua.ApplicationTypeClient,
		},
		nil,
		nil,
		request.EndpointURL,
		opcua.SecurityPolicyURINone,
		opcua.MessageSecurityModeNone,
		nil,
		defaultConnectTimeout,
		tls.Certificate{},
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

// RegisterServer registers a server with a discovery server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.5/
func (ch *clientSecureChannel) RegisterServer(ctx context.Context, request *opcua.RegisterServerRequest) (*opcua.RegisterServerResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.RegisterServerResponse), nil
}

// RegisterServer2 registers a server with a discovery server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.6/
func (ch *clientSecureChannel) RegisterServer2(ctx context.Context, request *opcua.RegisterServer2Request) (*opcua.RegisterServer2Response, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.RegisterServer2Response), nil
}

// RegisterServer registers a server with a discovery server.
// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.5/
func RegisterServer(ctx context.Context, endpointURL string, request *opcua.RegisterServerRequest) (*opcua.RegisterServerResponse, error) {
	ch := newClientSecureChannel(
		opcua.ApplicationDescription{
			ApplicationName: opcua.LocalizedText{Text: "RegistrationClient"},
			ApplicationType: opcua.ApplicationTypeClient,
		},
		nil,
		nil,
		endpointURL,
		opcua.SecurityPolicyURIBestAvailable,
		opcua.MessageSecurityModeInvalid,
		nil,
		defaultConnectTimeout,
		tls.Certificate{},
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
	res, err := ch.RegisterServer(ctx, request)
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

// RegisterServer2 registers a server with a discovery server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.6/
func RegisterServer2(ctx context.Context, endpointURL string, request *opcua.RegisterServer2Request) (*opcua.RegisterServer2Response, error) {
	ch := newClientSecureChannel(
		opcua.ApplicationDescription{
			ApplicationName: opcua.LocalizedText{Text: "RegistrationClient"},
			ApplicationType: opcua.ApplicationTypeClient,
		},
		nil,
		nil,
		endpointURL,
		opcua.SecurityPolicyURIBestAvailable,
		opcua.MessageSecurityModeInvalid,
		nil,
		defaultConnectTimeout,
		tls.Certificate{},
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
	res, err := ch.RegisterServer2(ctx, request)
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
func (ch *Client) createSession(ctx context.Context, request *opcua.CreateSessionRequest) (*opcua.CreateSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CreateSessionResponse), nil
}

// Activate a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.3/
func (ch *Client) activateSession(ctx context.Context, request *opcua.ActivateSessionRequest) (*opcua.ActivateSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.ActivateSessionResponse), nil
}

// Close a session.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.4/
func (ch *Client) closeSession(ctx context.Context, request *opcua.CloseSessionRequest) (*opcua.CloseSessionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CloseSessionResponse), nil
}

// Cancel sends a cancel request.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.5/
func (ch *Client) Cancel(ctx context.Context, request *opcua.CancelRequest) (*opcua.CancelResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CancelResponse), nil
}

// AddNodes adds one or more Nodes into the AddressSpace hierarchy.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.2/
func (ch *Client) AddNodes(ctx context.Context, request *opcua.AddNodesRequest) (*opcua.AddNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.AddNodesResponse), nil
}

// AddReferences adds one or more References to one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.3/
func (ch *Client) AddReferences(ctx context.Context, request *opcua.AddReferencesRequest) (*opcua.AddReferencesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.AddReferencesResponse), nil
}

// DeleteNodes deletes one or more Nodes from the AddressSpace.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.4/
func (ch *Client) DeleteNodes(ctx context.Context, request *opcua.DeleteNodesRequest) (*opcua.DeleteNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.DeleteNodesResponse), nil
}

// DeleteReferences deletes one or more References of a Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.7.5/
func (ch *Client) DeleteReferences(ctx context.Context, request *opcua.DeleteReferencesRequest) (*opcua.DeleteReferencesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.DeleteReferencesResponse), nil
}

// Browse discovers the References of a specified Node.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.2/
func (ch *Client) Browse(ctx context.Context, request *opcua.BrowseRequest) (*opcua.BrowseResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.BrowseResponse), nil
}

// BrowseNext requests the next set of Browse responses, when the information is too large to be sent in a single response.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.3/
func (ch *Client) BrowseNext(ctx context.Context, request *opcua.BrowseNextRequest) (*opcua.BrowseNextResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.BrowseNextResponse), nil
}

// TranslateBrowsePathsToNodeIDs translates one or more browse paths to NodeIDs.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.4/
func (ch *Client) TranslateBrowsePathsToNodeIDs(ctx context.Context, request *opcua.TranslateBrowsePathsToNodeIDsRequest) (*opcua.TranslateBrowsePathsToNodeIDsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.TranslateBrowsePathsToNodeIDsResponse), nil
}

// RegisterNodes registers the Nodes that will be accessed repeatedly (e.g. Write, Call).
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.5/
func (ch *Client) RegisterNodes(ctx context.Context, request *opcua.RegisterNodesRequest) (*opcua.RegisterNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.RegisterNodesResponse), nil
}

// UnregisterNodes unregisters NodeIDs that have been obtained via the RegisterNodes service.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.6/
func (ch *Client) UnregisterNodes(ctx context.Context, request *opcua.UnregisterNodesRequest) (*opcua.UnregisterNodesResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.UnregisterNodesResponse), nil
}

// Read returns values of Attributes of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.2/
func (ch *Client) Read(ctx context.Context, request *opcua.ReadRequest) (*opcua.ReadResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.ReadResponse), nil
}

// Write sets values of Attributes of one or more Nodes
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.4/
func (ch *Client) Write(ctx context.Context, request *opcua.WriteRequest) (*opcua.WriteResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.WriteResponse), nil
}

// HistoryRead returns historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.3/
func (ch *Client) HistoryRead(ctx context.Context, request *opcua.HistoryReadRequest) (*opcua.HistoryReadResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.HistoryReadResponse), nil
}

// HistoryUpdate sets historical values or events of one or more Nodes.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.10.5/
func (ch *Client) HistoryUpdate(ctx context.Context, request *opcua.HistoryUpdateRequest) (*opcua.HistoryUpdateResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.HistoryUpdateResponse), nil
}

// Call invokes a list of Methods.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.11.2/
func (ch *Client) Call(ctx context.Context, request *opcua.CallRequest) (*opcua.CallResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CallResponse), nil
}

// CreateMonitoredItems creates and adds one or more MonitoredItems to a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.2/
func (ch *Client) CreateMonitoredItems(ctx context.Context, request *opcua.CreateMonitoredItemsRequest) (*opcua.CreateMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CreateMonitoredItemsResponse), nil
}

// ModifyMonitoredItems modifies MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.3/
func (ch *Client) ModifyMonitoredItems(ctx context.Context, request *opcua.ModifyMonitoredItemsRequest) (*opcua.ModifyMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.ModifyMonitoredItemsResponse), nil
}

// SetMonitoringMode sets the monitoring mode for one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.4/
func (ch *Client) SetMonitoringMode(ctx context.Context, request *opcua.SetMonitoringModeRequest) (*opcua.SetMonitoringModeResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.SetMonitoringModeResponse), nil
}

// SetTriggering creates and deletes triggering links for a triggering item.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.5/
func (ch *Client) SetTriggering(ctx context.Context, request *opcua.SetTriggeringRequest) (*opcua.SetTriggeringResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.SetTriggeringResponse), nil
}

// DeleteMonitoredItems removes one or more MonitoredItems of a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.12.6/
func (ch *Client) DeleteMonitoredItems(ctx context.Context, request *opcua.DeleteMonitoredItemsRequest) (*opcua.DeleteMonitoredItemsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.DeleteMonitoredItemsResponse), nil
}

// CreateSubscription creates a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.2/
func (ch *Client) CreateSubscription(ctx context.Context, request *opcua.CreateSubscriptionRequest) (*opcua.CreateSubscriptionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.CreateSubscriptionResponse), nil
}

// ModifySubscription modifies a Subscription.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.3/
func (ch *Client) ModifySubscription(ctx context.Context, request *opcua.ModifySubscriptionRequest) (*opcua.ModifySubscriptionResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.ModifySubscriptionResponse), nil
}

// SetPublishingMode enables sending of Notifications on one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.4/
func (ch *Client) SetPublishingMode(ctx context.Context, request *opcua.SetPublishingModeRequest) (*opcua.SetPublishingModeResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.SetPublishingModeResponse), nil
}

// Publish requests the Server to return a NotificationMessage or a keep-alive Message.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.5/
func (ch *Client) Publish(ctx context.Context, request *opcua.PublishRequest) (*opcua.PublishResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.PublishResponse), nil
}

// Republish requests the Server to republish a NotificationMessage from its retransmission queue.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.6/
func (ch *Client) Republish(ctx context.Context, request *opcua.RepublishRequest) (*opcua.RepublishResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.RepublishResponse), nil
}

// TransferSubscriptions ransfers a Subscription and its MonitoredItems from one Session to another.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.7/
func (ch *Client) TransferSubscriptions(ctx context.Context, request *opcua.TransferSubscriptionsRequest) (*opcua.TransferSubscriptionsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.TransferSubscriptionsResponse), nil
}

// DeleteSubscriptions deletes one or more Subscriptions.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.13.8/
func (ch *Client) DeleteSubscriptions(ctx context.Context, request *opcua.DeleteSubscriptionsRequest) (*opcua.DeleteSubscriptionsResponse, error) {
	response, err := ch.request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*opcua.DeleteSubscriptionsResponse), nil
}
