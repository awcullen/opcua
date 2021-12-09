// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// EncodingContext provides a table of NamespaceURIs for encoders/decoders.
type EncodingContext interface {
	NamespaceURIs() []string
}

type encodingContext struct {
	namespaceURIs []string
}

// NewEncodingContext constructs a default EncodingContext.
func NewEncodingContext() EncodingContext {
	return &encodingContext{[]string{"http://opcfoundation.org/UA/"}}
}

// NamespaceURIs returns a slice of NamespaceURI
func (ec *encodingContext) NamespaceURIs() []string {
	return ec.namespaceURIs
}
