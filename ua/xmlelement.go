// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"regexp"
)

var (
	validXML = regexp.MustCompile(`[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000-x10FFFF]+`)
)

// XMLElement is stored as string
type XMLElement string

// String returns element as a string.
func (e XMLElement) String() string {
	return validXML.ReplaceAllString(string(e), "")
}
