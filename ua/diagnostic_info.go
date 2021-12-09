// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

// DiagnosticInfo holds additional info regarding errors in service calls.
type DiagnosticInfo struct {
	// SymbolicID returns the SymbolicID.
	SymbolicID *int32 `json:",omitempty"`
	// NamespaceURI returns the index of the NamespaceURI.
	NamespaceURI *int32 `json:",omitempty"`
	// Locale returns the index of the Locale.
	Locale *int32 `json:",omitempty"`
	// LocalizedText returns the index of the LocalizedText.
	LocalizedText *int32 `json:",omitempty"`
	// AdditionalInfo returns the AdditionalInfo.
	AdditionalInfo *string `json:",omitempty"`
	// InnerStatusCode returns the InnerStatusCode.
	InnerStatusCode *StatusCode `json:",omitempty"`
	// InnerDiagnosticInfo returns the InnerDiagnosticInfo.
	InnerDiagnosticInfo *DiagnosticInfo `json:",omitempty"`
}
