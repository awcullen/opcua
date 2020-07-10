// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"crypto/cipher"
	"hash"
	"time"
)

// TODO: implement list 
type securityToken struct {
	channelID                  uint32
	tokenID                    uint32
	createdAt                  time.Time
	lifetime                   int
	localNonce                 []byte
	remoteNonce                []byte
	localSigningKey            []byte
	localEncryptingKey         []byte
	localInitializationVector  []byte
	remoteSigningKey           []byte
	remoteEncryptingKey        []byte
	remoteInitializationVector []byte
	localHmac                  hash.Hash
	remoteHmac                 hash.Hash
	localEncryptor             cipher.Block
	remoteEncryptor            cipher.Block
}
