// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

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

// SecurityPolicyNone ...
type SecurityPolicyNone struct {
}

// PolicyURI ...
func (p *SecurityPolicyNone) PolicyURI() string { return SecurityPolicyURINone }

// RSASign ...
func (p *SecurityPolicyNone) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// RSAVerify ...
func (p *SecurityPolicyNone) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	return BadSecurityPolicyRejected
}

// RSAEncrypt ...
func (p *SecurityPolicyNone) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// RSADecrypt ...
func (p *SecurityPolicyNone) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return nil, BadSecurityPolicyRejected
}

// SymHMACFactory ...
func (p *SecurityPolicyNone) SymHMACFactory(key []byte) hash.Hash {
	return nil
}

// RSAPaddingSize ...
func (p *SecurityPolicyNone) RSAPaddingSize() int { return 0 }

// SymSignatureSize ...
func (p *SecurityPolicyNone) SymSignatureSize() int { return 0 }

// SymSignatureKeySize ...
func (p *SecurityPolicyNone) SymSignatureKeySize() int { return 0 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyNone) SymEncryptionBlockSize() int { return 1 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyNone) SymEncryptionKeySize() int { return 0 }

// NonceSize ...
func (p *SecurityPolicyNone) NonceSize() int { return 0 }

// SecurityPolicyBasic128Rsa15 ...
type SecurityPolicyBasic128Rsa15 struct {
}

// PolicyURI ...
func (p *SecurityPolicyBasic128Rsa15) PolicyURI() string { return SecurityPolicyURIBasic128Rsa15 }

// RSASign ...
func (p *SecurityPolicyBasic128Rsa15) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha1.Sum(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
}

// RSAVerify ...
func (p *SecurityPolicyBasic128Rsa15) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha1.Sum(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
}

// RSAEncrypt ...
func (p *SecurityPolicyBasic128Rsa15) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plainText)
}

// RSADecrypt ...
func (p *SecurityPolicyBasic128Rsa15) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherText)
}

// SymHMACFactory ...
func (p *SecurityPolicyBasic128Rsa15) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}

// RSAPaddingSize ...
func (p *SecurityPolicyBasic128Rsa15) RSAPaddingSize() int { return 11 }

// SymSignatureSize ...
func (p *SecurityPolicyBasic128Rsa15) SymSignatureSize() int { return 20 }

// SymSignatureKeySize ...
func (p *SecurityPolicyBasic128Rsa15) SymSignatureKeySize() int { return 16 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyBasic128Rsa15) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyBasic128Rsa15) SymEncryptionKeySize() int { return 16 }

// NonceSize ...
func (p *SecurityPolicyBasic128Rsa15) NonceSize() int { return 16 }

// SecurityPolicyBasic256 ...
type SecurityPolicyBasic256 struct {
}

// PolicyURI ...
func (p *SecurityPolicyBasic256) PolicyURI() string { return SecurityPolicyURIBasic256 }

// RSASign ...
func (p *SecurityPolicyBasic256) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha1.Sum(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
}

// RSAVerify ...
func (p *SecurityPolicyBasic256) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha1.Sum(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
}

// RSAEncrypt ...
func (p *SecurityPolicyBasic256) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *SecurityPolicyBasic256) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *SecurityPolicyBasic256) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}

// RSAPaddingSize ...
func (p *SecurityPolicyBasic256) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *SecurityPolicyBasic256) SymSignatureSize() int { return 20 }

// SymSignatureKeySize ...
func (p *SecurityPolicyBasic256) SymSignatureKeySize() int { return 24 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyBasic256) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyBasic256) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *SecurityPolicyBasic256) NonceSize() int { return 32 }

// SecurityPolicyBasic256Sha256 ...
type SecurityPolicyBasic256Sha256 struct {
}

// PolicyURI ...
func (p *SecurityPolicyBasic256Sha256) PolicyURI() string { return SecurityPolicyURIBasic256Sha256 }

// RSASign ...
func (p *SecurityPolicyBasic256Sha256) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// RSAVerify ...
func (p *SecurityPolicyBasic256Sha256) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

// RSAEncrypt ...
func (p *SecurityPolicyBasic256Sha256) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *SecurityPolicyBasic256Sha256) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *SecurityPolicyBasic256Sha256) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *SecurityPolicyBasic256Sha256) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *SecurityPolicyBasic256Sha256) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *SecurityPolicyBasic256Sha256) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyBasic256Sha256) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyBasic256Sha256) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *SecurityPolicyBasic256Sha256) NonceSize() int { return 32 }

// SecurityPolicyAes128Sha256RsaOaep ...
type SecurityPolicyAes128Sha256RsaOaep struct {
}

// PolicyURI ...
func (p *SecurityPolicyAes128Sha256RsaOaep) PolicyURI() string {
	return SecurityPolicyURIAes128Sha256RsaOaep
}

// RSASign ...
func (p *SecurityPolicyAes128Sha256RsaOaep) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// RSAVerify ...
func (p *SecurityPolicyAes128Sha256RsaOaep) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

// RSAEncrypt ...
func (p *SecurityPolicyAes128Sha256RsaOaep) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *SecurityPolicyAes128Sha256RsaOaep) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *SecurityPolicyAes128Sha256RsaOaep) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) RSAPaddingSize() int { return 42 }

// SymSignatureSize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) SymEncryptionKeySize() int { return 16 }

// NonceSize ...
func (p *SecurityPolicyAes128Sha256RsaOaep) NonceSize() int { return 32 }

// SecurityPolicyAes256Sha256RsaPss ...
type SecurityPolicyAes256Sha256RsaPss struct {
}

// PolicyURI ...
func (p *SecurityPolicyAes256Sha256RsaPss) PolicyURI() string {
	return SecurityPolicyURIAes256Sha256RsaPss
}

// RSASign ...
func (p *SecurityPolicyAes256Sha256RsaPss) RSASign(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	hashed := sha256.Sum256(plainText)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// RSAVerify ...
func (p *SecurityPolicyAes256Sha256RsaPss) RSAVerify(pub *rsa.PublicKey, plainText, signature []byte) error {
	hashed := sha256.Sum256(plainText)
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// RSAEncrypt ...
func (p *SecurityPolicyAes256Sha256RsaPss) RSAEncrypt(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plainText, []byte{})
}

// RSADecrypt ...
func (p *SecurityPolicyAes256Sha256RsaPss) RSADecrypt(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherText, []byte{})
}

// SymHMACFactory ...
func (p *SecurityPolicyAes256Sha256RsaPss) SymHMACFactory(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// RSAPaddingSize ...
func (p *SecurityPolicyAes256Sha256RsaPss) RSAPaddingSize() int { return 66 }

// SymSignatureSize ...
func (p *SecurityPolicyAes256Sha256RsaPss) SymSignatureSize() int { return 32 }

// SymSignatureKeySize ...
func (p *SecurityPolicyAes256Sha256RsaPss) SymSignatureKeySize() int { return 32 }

// SymEncryptionBlockSize ...
func (p *SecurityPolicyAes256Sha256RsaPss) SymEncryptionBlockSize() int { return 16 }

// SymEncryptionKeySize ...
func (p *SecurityPolicyAes256Sha256RsaPss) SymEncryptionKeySize() int { return 32 }

// NonceSize ...
func (p *SecurityPolicyAes256Sha256RsaPss) NonceSize() int { return 32 }
