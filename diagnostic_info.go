// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

// DiagnosticInfo holds additional info regarding errors in service calls.
type DiagnosticInfo struct {
	symbolicID          int32
	namespaceURI        int32
	locale              int32
	localizedText       int32
	additionalInfo      string
	innerStatusCode     StatusCode
	innerDiagnosticInfo *DiagnosticInfo
}

// NewDiagnosticInfo constructs new NewDiagnosticInfo
func NewDiagnosticInfo(symbolicID int32, namespaceURI int32, locale int32, localizedText int32, additionalInfo string, innerStatusCode StatusCode, innerDiagnosticInfo *DiagnosticInfo) *DiagnosticInfo {
	return &DiagnosticInfo{symbolicID, namespaceURI, locale, localizedText, additionalInfo, innerStatusCode, innerDiagnosticInfo}
}

// SymbolicID returns the SymbolicID.
func (info *DiagnosticInfo) SymbolicID() int32 {
	return info.symbolicID
}

// NamespaceURI returns the index of the NamespaceURI.
func (info *DiagnosticInfo) NamespaceURI() int32 {
	return info.namespaceURI
}

// Locale returns the index of the Locale.
func (info *DiagnosticInfo) Locale() int32 {
	return info.locale
}

// LocalizedText returns the index of the LocalizedText.
func (info *DiagnosticInfo) LocalizedText() int32 {
	return info.localizedText
}

// AdditionalInfo returns the AdditionalInfo.
func (info *DiagnosticInfo) AdditionalInfo() string {
	return info.additionalInfo
}

// InnerStatusCode returns the InnerStatusCode.
func (info *DiagnosticInfo) InnerStatusCode() StatusCode {
	return info.innerStatusCode
}

// InnerDiagnosticInfo returns the InnerDiagnosticInfo.
func (info *DiagnosticInfo) InnerDiagnosticInfo() *DiagnosticInfo {
	return info.innerDiagnosticInfo
}

// NilDiagnosticInfo is the nil value.
var NilDiagnosticInfo = DiagnosticInfo{}
