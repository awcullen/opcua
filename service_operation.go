// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

// serviceOperation holds a request and response channel.
type serviceOperation struct {
	request    ServiceRequest
	responseCh chan ServiceResponse
}

// newServiceOperation constructs a new ServiceOperation
func newServiceOperation(request ServiceRequest, responseCh chan ServiceResponse) *serviceOperation {
	return &serviceOperation{request, responseCh}
}

// Request returns the request that started the operation.
func (o *serviceOperation) Request() ServiceRequest {
	return o.request
}

// ResponseCh returns a channel that produces the response.
func (o *serviceOperation) ResponseCh() chan ServiceResponse {
	return o.responseCh
}
