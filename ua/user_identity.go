// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"crypto/rsa"
)

// AnonymousIdentity provides no identity to server when activating a session.
type AnonymousIdentity struct {
}

// UserNameIdentity provides userName and password to server when activating a session.
type UserNameIdentity struct {
	UserName string
	Password string
}

// X509Identity provides x509 certificate to server when activating a session.
type X509Identity struct {
	Certificate ByteString
	Key         *rsa.PrivateKey
}

// IssuedIdentity provides issued token data to server when activating a session.
type IssuedIdentity struct {
	TokenData ByteString
}
