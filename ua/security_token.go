// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"crypto/cipher"
	"hash"
	"time"
)

// TODO: implement list
type SecurityToken struct {
	ChannelID                  uint32
	TokenID                    uint32
	CreatedAt                  time.Time
	Lifetime                   int
	LocalNonce                 []byte
	RemoteNonce                []byte
	LocalSigningKey            []byte
	LocalEncryptingKey         []byte
	LocalInitializationVector  []byte
	RemoteSigningKey           []byte
	RemoteEncryptingKey        []byte
	RemoteInitializationVector []byte
	LocalHmac                  hash.Hash
	RemoteHmac                 hash.Hash
	LocalEncryptor             cipher.Block
	RemoteEncryptor            cipher.Block
}
