// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
)

// FindServers returns the Servers known to a Server or Discovery Server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func (ch *clientSecureChannel) FindServers(ctx context.Context, request *FindServersRequest) (*FindServersResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*FindServersResponse), nil
}

// GetEndpoints returns the endpoint descriptions supported by the server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/
func (ch *clientSecureChannel) GetEndpoints(ctx context.Context, request *GetEndpointsRequest) (*GetEndpointsResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*GetEndpointsResponse), nil
}

// FindServers returns the Servers known to a Server or Discovery Server
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.2/
func FindServers(ctx context.Context, request *FindServersRequest) (*FindServersResponse, error) {
	ch := newClientSecureChannel(
		&ApplicationDescription{
			ApplicationName: LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: ApplicationTypeClient,
		},
		nil,
		nil,
		&EndpointDescription{
			EndpointURL:       request.EndpointURL,
			SecurityMode:      MessageSecurityModeNone,
			SecurityPolicyURI: SecurityPolicyURINone,
		},
		newClientSecureChannelOptions(),
	)
	ch.trace = true
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
func GetEndpoints(ctx context.Context, request *GetEndpointsRequest) (*GetEndpointsResponse, error) {
	ch := newClientSecureChannel(
		&ApplicationDescription{
			ApplicationName: LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: ApplicationTypeClient,
		},
		nil,
		nil,
		&EndpointDescription{
			EndpointURL:       request.EndpointURL,
			SecurityMode:      MessageSecurityModeNone,
			SecurityPolicyURI: SecurityPolicyURINone,
		},
		newClientSecureChannelOptions(),
	)
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
func (ch *clientSecureChannel) RegisterServer(ctx context.Context, request *RegisterServerRequest) (*RegisterServerResponse, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*RegisterServerResponse), nil
}

// RegisterServer2 registers a server with a discovery server.
// See https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.6/
func (ch *clientSecureChannel) RegisterServer2(ctx context.Context, request *RegisterServer2Request) (*RegisterServer2Response, error) {
	response, err := ch.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.(*RegisterServer2Response), nil
}

// RegistrationClientOptions contains the DiscoveryClient options.
type RegistrationClientOptions struct {
	clientSecureChannelOptions
	RemoteEndpoint *EndpointDescription
}

// NewRegistrationClientOptions initializes a UaTcpRegistrationClientOptions structure with default values.
func NewRegistrationClientOptions() RegistrationClientOptions {
	return RegistrationClientOptions{
		clientSecureChannelOptions: newClientSecureChannelOptions(),
		RemoteEndpoint: &EndpointDescription{
			EndpointURL:       "opc.tcp://127.0.0.1:4840",
			SecurityPolicyURI: SecurityPolicyURIBestAvailable,
		},
	}
}

// RegisterServer registers a server with a discovery server.
// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.5/
func RegisterServer(ctx context.Context, request *RegisterServerRequest, opts RegistrationClientOptions) (*RegisterServerResponse, error) {
	ch := newClientSecureChannel(
		&ApplicationDescription{
			ApplicationName: LocalizedText{Text: "RegistrationClient"},
			ApplicationType: ApplicationTypeClient,
		},
		nil,
		nil,
		opts.RemoteEndpoint,
		opts.clientSecureChannelOptions,
	)
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
func RegisterServer2(ctx context.Context, request *RegisterServer2Request, opts RegistrationClientOptions) (*RegisterServer2Response, error) {
	ch := newClientSecureChannel(
		&ApplicationDescription{
			ApplicationName: LocalizedText{Text: "RegistrationClient"},
			ApplicationType: ApplicationTypeClient,
		},
		nil,
		nil,
		opts.RemoteEndpoint,
		opts.clientSecureChannelOptions,
	)
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
