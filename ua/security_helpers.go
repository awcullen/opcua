package ua

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

// GetNextNonce gets next random nonce of requested length.
func GetNextNonce(length int) []byte {
	var nonce = make([]byte, length)
	rand.Read(nonce)
	return nonce
}

// Prf calculates the pseudo random function. [adapted from crypto/tls/prf.go]
func Prf(secret, seed []byte, keyLen int, securityPolicyURI string) []byte {
	var h hash.Hash
	switch securityPolicyURI {
	case SecurityPolicyURIBasic128Rsa15, SecurityPolicyURIBasic256:
		h = hmac.New(sha1.New, secret)
	default:
		h = hmac.New(sha256.New, secret)
	}
	result := make([]byte, keyLen)
	a := seed

	j := 0
	for j < len(result) {
		h.Write(a)
		a = h.Sum(nil)
		h.Reset()

		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		h.Reset()
		copy(result[j:], b)
		j += len(b)
	}

	return result
}
