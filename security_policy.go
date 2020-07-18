// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

// SecurityPolicyURIs
const (
	SecurityPolicyURINone                = "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityPolicyURIBasic128Rsa15       = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
	SecurityPolicyURIBasic256            = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
	SecurityPolicyURIBasic256Sha256      = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	SecurityPolicyURIAes128Sha256RsaOaep = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	SecurityPolicyURIAes256Sha256RsaPss  = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
	SecurityPolicyURIBestAvailable       = ""
)

// SecurityPolicy is a mapping of PolicyURI to security settings
type SecurityPolicy interface {
	PolicyURI() string
	RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error)
	RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error
	RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error)
	RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error)
	SymHMACFactory(key []byte) hash.Hash
	RSAPaddingSize() int
	SymSignatureSize() int
	SymSignatureKeySize() int
	SymEncryptionBlockSize() int
	SymEncryptionKeySize() int
	NonceSize() int
}

// securityPolicyNone ...
type securityPolicyNone struct {
}

func newSecurityPolicyNone() *securityPolicyNone {
	return &securityPolicyNone{}
}

// PolicyURI ...
func (p *securityPolicyNone) PolicyURI() string { return SecurityPolicyURINone }

// RSASign ...
func (p *securityPolicyNone) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// RSAVerify ...
func (p *securityPolicyNone) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	return BadSecurityPolicyRejected
}

// RSAEncrypt ...
func (p *securityPolicyNone) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// RSADecrypt ...
func (p *securityPolicyNone) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// SymHMACFactory ...
func (p *securityPolicyNone) SymHMACFactory(key []byte) hash.Hash {
	return nil
}

// RSAPaddingSize ...
func (p *securityPolicyNone) RSAPaddingSize() int { return 0 }

// SymSignatureSize ...
func (p *securityPolicyNone) SymSignatureSize() int { return 0 }

// SymSignatureKeySize ...
func (p *securityPolicyNone) SymSignatureKeySize() int { return 0 }

// SymEncryptionBlockSize ...
func (p *securityPolicyNone) SymEncryptionBlockSize() int { return 1 }

// SymEncryptionKeySize ...
func (p *securityPolicyNone) SymEncryptionKeySize() int { return 0 }

// NonceSize ...
func (p *securityPolicyNone) NonceSize() int { return 0 }

// securityPolicyBasic128Rsa15 ...
type securityPolicyBasic128Rsa15 struct {
}

// PolicyURI ...
func (p *securityPolicyBasic128Rsa15) PolicyURI() string { return SecurityPolicyURIBasic128Rsa15 }

// RSASign ...
func (p *securityPolicyBasic128Rsa15) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha1.Sum(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
}

// RSAVerify ...
func (p *securityPolicyBasic128Rsa15) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha1.Sum(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
}

// RSAEncrypt ...
func (p *securityPolicyBasic128Rsa15) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plainText)
}

// RSADecrypt ...
func (p *securityPolicyBasic128Rsa15) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherText)
}

// SymHMACFactory ...
func (p *securityPolicyBasic128Rsa15) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}

// RSAPaddingSize ...
func (p *securityPolicyBasic128Rsa15) RSAPaddingSize() int { return 11 }

// SymSignatureSize ...
func (p *securityPolicyBasic128Rsa15) SymSignatureSize() int { return 20 }

// SymSignatureKeySize ...
func (p *securityPolicyBasic128Rsa15) SymSignatureKeySize() int { return 16 }

// SymEncryptionBlockSize ...
func (p *securityPolicyBasic128Rsa15) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *securityPolicyBasic128Rsa15) SymEncryptionKeySize() int { return 16 }

// NonceSize ...
func (p *securityPolicyBasic128Rsa15) NonceSize() int { return 16 }

// securityPolicyBasic256 ...
type securityPolicyBasic256 struct {
}

// PolicyURI ...
func (p *securityPolicyBasic256) PolicyURI() string { return SecurityPolicyURIBasic256 }

// RSASign ...
func (p *securityPolicyBasic256) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha1.Sum(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
}

// RSAVerify ...
func (p *securityPolicyBasic256) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha1.Sum(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
}

// RSAEncrypt ...
func (p *securityPolicyBasic256) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *securityPolicyBasic256) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *securityPolicyBasic256) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}

// RSAPaddingSize ...
func (p *securityPolicyBasic256) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *securityPolicyBasic256) SymSignatureSize() int { return 20 }

// SymSignatureKeySize ...
func (p *securityPolicyBasic256) SymSignatureKeySize() int { return 24 }

// SymEncryptionBlockSize ...
func (p *securityPolicyBasic256) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *securityPolicyBasic256) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *securityPolicyBasic256) NonceSize() int { return 32 }

// securityPolicyBasic256Sha256 ...
type securityPolicyBasic256Sha256 struct {
}

// PolicyURI ...
func (p *securityPolicyBasic256Sha256) PolicyURI() string { return SecurityPolicyURIBasic256Sha256 }

// RSASign ...
func (p *securityPolicyBasic256Sha256) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// RSAVerify ...
func (p *securityPolicyBasic256Sha256) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

// RSAEncrypt ...
func (p *securityPolicyBasic256Sha256) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *securityPolicyBasic256Sha256) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *securityPolicyBasic256Sha256) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *securityPolicyBasic256Sha256) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *securityPolicyBasic256Sha256) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *securityPolicyBasic256Sha256) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *securityPolicyBasic256Sha256) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *securityPolicyBasic256Sha256) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *securityPolicyBasic256Sha256) NonceSize() int { return 32 }

// securityPolicyAes128Sha256RsaOaep ...
type securityPolicyAes128Sha256RsaOaep struct {
}

// PolicyURI ...
func (p *securityPolicyAes128Sha256RsaOaep) PolicyURI() string {
	return SecurityPolicyURIAes128Sha256RsaOaep
}

// RSASign ...
func (p *securityPolicyAes128Sha256RsaOaep) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// RSAVerify ...
func (p *securityPolicyAes128Sha256RsaOaep) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

// RSAEncrypt ...
func (p *securityPolicyAes128Sha256RsaOaep) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *securityPolicyAes128Sha256RsaOaep) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *securityPolicyAes128Sha256RsaOaep) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *securityPolicyAes128Sha256RsaOaep) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *securityPolicyAes128Sha256RsaOaep) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *securityPolicyAes128Sha256RsaOaep) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *securityPolicyAes128Sha256RsaOaep) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *securityPolicyAes128Sha256RsaOaep) SymEncryptionKeySize() int { return 16 }

// NonceSize ...
func (p *securityPolicyAes128Sha256RsaOaep) NonceSize() int { return 32 }

// securityPolicyAes256Sha256RsaPss ...
type securityPolicyAes256Sha256RsaPss struct {
}

// PolicyURI ...
func (p *securityPolicyAes256Sha256RsaPss) PolicyURI() string {
	return SecurityPolicyURIAes256Sha256RsaPss
}

// RSASign ...
func (p *securityPolicyAes256Sha256RsaPss) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// RSAVerify ...
func (p *securityPolicyAes256Sha256RsaPss) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// RSAEncrypt ...
func (p *securityPolicyAes256Sha256RsaPss) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *securityPolicyAes256Sha256RsaPss) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *securityPolicyAes256Sha256RsaPss) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *securityPolicyAes256Sha256RsaPss) RSAPaddingSize() int { return 66 }

// SymSignatureSize ...
func (p *securityPolicyAes256Sha256RsaPss) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *securityPolicyAes256Sha256RsaPss) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *securityPolicyAes256Sha256RsaPss) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *securityPolicyAes256Sha256RsaPss) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *securityPolicyAes256Sha256RsaPss) NonceSize() int { return 32 }
