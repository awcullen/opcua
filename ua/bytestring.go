// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"encoding/base64"
)

// ByteString is stored as a string.
type ByteString string

// String returns ByteString as a base64-encoded string.
func (b ByteString) String() string {
	return base64.StdEncoding.EncodeToString([]byte(b))
}

func (b ByteString) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}
