// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// ServiceRequest is a request for a service.
type ServiceRequest interface {
	Header() *RequestHeader
}

// Header returns the request header.
func (h *RequestHeader) Header() *RequestHeader {
	return h
}

// ServiceResponse is a response from a service.
type ServiceResponse interface {
	Header() *ResponseHeader
}

// Header returns the response header.
func (h *ResponseHeader) Header() *ResponseHeader {
	return h
}

// ResponseWriter is used to write a response to the client.
type ResponseWriter interface {
	// Write a response to the client.
	Write(res ServiceResponse) error
}
