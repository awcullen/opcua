// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"fmt"
)

// LocalizedText pairs text and a Locale string.
type LocalizedText struct {
	Text   string `xml:",innerxml"`
	Locale string `xml:"Locale,attr"`
}

// NewLocalizedText constructs a LocalizedText from text and Locale string.
func NewLocalizedText(text, locale string) LocalizedText {
	return LocalizedText{text, locale}
}

// String returns the string representation, e.g. "text (locale)"
func (a LocalizedText) String() string {
	return fmt.Sprintf("%s (%s)", a.Text, a.Locale)
}
