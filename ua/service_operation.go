// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// ServiceOperation holds a request and response channel.
type ServiceOperation struct {
	request    ServiceRequest
	responseCh chan ServiceResponse
}

// NewServiceOperation constructs a new ServiceOperation
func NewServiceOperation(request ServiceRequest, responseCh chan ServiceResponse) *ServiceOperation {
	return &ServiceOperation{request, responseCh}
}

// Request returns the request that started the operation.
func (o *ServiceOperation) Request() ServiceRequest {
	return o.request
}

// ResponseCh returns a channel that produces the response.
func (o *ServiceOperation) ResponseCh() chan ServiceResponse {
	return o.responseCh
}
