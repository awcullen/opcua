// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"sort"

	"github.com/djherbis/buffer"
)

const (
	defaultSessionTimeout float64 = 120 * 1000
	nonceLength           int     = 32
)

// clientOptions contains the client options.
type clientOptions struct {
	clientSecureChannelOptions
	// The uri of the security policy.
	SecurityPolicyURI string
	// The identity of the local user. May be AnonymousIdentity, UserNameIdentity, X509Identity, or IssuedIdentity
	UserIdentity interface{}
	// The name of the Session.
	SessionName string
	// The number of milliseconds that a session may be unused before being closed by the server. (default: 2 min)
	SessionTimeout float64
	// The application name.
	ApplicationName string
}

// newClientOptions initializes a clientOptions structure with default values.
func newclientOptions() *clientOptions {
	return &clientOptions{
		clientSecureChannelOptions: newClientSecureChannelOptions(),
		SecurityPolicyURI:          SecurityPolicyURIBestAvailable,
		UserIdentity:               new(AnonymousIdentity),
		SessionTimeout:             defaultSessionTimeout,
		ApplicationName:            "awcullen/opcua",
	}
}

// NewClient returns a client connected to an OPC UA server with the given URL and options.
func NewClient(ctx context.Context, endpointURL string, opts ...ClientOption) (c *Client, err error) {

	// apply each option to the default
	var options = newclientOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	// get endpoints from discovery url
	req := &GetEndpointsRequest{
		EndpointURL: endpointURL,
		ProfileURIs: []string{TransportProfileURIUaTcpTransport},
	}
	res, err := GetEndpoints(ctx, req)
	if err != nil {
		return nil, err
	}

	// order endpoints by decreasing security level.
	var orderedEndpoints = res.Endpoints
	sort.Slice(orderedEndpoints, func(i, j int) bool {
		return orderedEndpoints[i].SecurityLevel > orderedEndpoints[j].SecurityLevel
	})

	// if client certificate is not set then limit secuity policy to none
	securityPolicyURI := options.SecurityPolicyURI
	if securityPolicyURI == SecurityPolicyURIBestAvailable && len(options.ApplicationCertificate.Certificate) == 0 {
		securityPolicyURI = SecurityPolicyURINone
	}

	// select first endpoint with matching policy uri.
	var selectedEndpoint *EndpointDescription
	for _, e := range orderedEndpoints {
		// filter out unsupported policy uri
		switch e.SecurityPolicyURI {
		case SecurityPolicyURINone, SecurityPolicyURIBasic128Rsa15,
			SecurityPolicyURIBasic256, SecurityPolicyURIBasic256Sha256,
			SecurityPolicyURIAes128Sha256RsaOaep, SecurityPolicyURIAes256Sha256RsaPss:
		default:
			continue
		}
		// if policy uri is empty string, select the first endpoint
		if securityPolicyURI == "" {
			selectedEndpoint = e
			break
		}
		// if policy uri is a match
		if e.SecurityPolicyURI == securityPolicyURI {
			selectedEndpoint = e
			break
		}
	}
	if selectedEndpoint == nil {
		return nil, BadUnexpectedError
	}

	localDescription := &ApplicationDescription{
		ApplicationName: LocalizedText{Text: options.ApplicationName},
		ApplicationType: ApplicationTypeClient,
	}

	var localCertificate []byte
	var localPrivateKey *rsa.PrivateKey
	if len(options.ApplicationCertificate.Certificate) > 0 {
		// if crt, key, err := GetCertificateFromFile(options.CertFile, options.KeyFile); err == nil {
		localCertificate = options.ApplicationCertificate.Certificate[0]
		localPrivateKey = options.ApplicationCertificate.PrivateKey.(*rsa.PrivateKey)
		crt, _ := x509.ParseCertificate(localCertificate)
		// if cert has URI then update local description
		if len(crt.URIs) > 0 {
			localDescription.ApplicationURI = crt.URIs[0].String()
		}
		// }
	}

	ch := &Client{
		channel:          newClientSecureChannel(localDescription, localCertificate, localPrivateKey, selectedEndpoint, options.clientSecureChannelOptions),
		localDescription: localDescription,
		remoteEndpoint:   selectedEndpoint,
		userIdentity:     options.UserIdentity,
		sessionName:      options.SessionName,
		sessionTimeout:   options.SessionTimeout,
	}

	// open session and read the namespace table
	if err := ch.open(ctx); err != nil {
		ch.Abort(ctx)
		return nil, err
	}

	return ch, nil
}

// Client for exchanging binary encoded requests and responses with an OPC UA server.
// Uses TCP based network protocol with the binary security protocol UA-SecureConversation 1.0 and the binary message encoding UA-Binary 1.0.
type Client struct {
	channel                *clientSecureChannel
	localDescription       *ApplicationDescription
	remoteEndpoint         *EndpointDescription
	userIdentity           interface{}
	sessionID              NodeID
	sessionName            string
	sessionTimeout         float64
	clientSignature        *SignatureData
	identityToken          interface{}
	identityTokenSignature *SignatureData
}

// SessionID gets the session id provided by the server.
func (ch *Client) SessionID() NodeID {
	return ch.sessionID
}

// EndpointURL gets the EndpointURL of the server.
func (ch *Client) EndpointURL() string {
	return ch.remoteEndpoint.EndpointURL
}

// SecurityPolicyURI gets the SecurityPolicyURI of the secure channel.
func (ch *Client) SecurityPolicyURI() string {
	return ch.remoteEndpoint.SecurityPolicyURI
}

// SecurityMode gets the MessageSecurityMode of the secure channel.
func (ch *Client) SecurityMode() MessageSecurityMode {
	return ch.remoteEndpoint.SecurityMode
}

// Request sends a service request to the server and returns the response.
func (ch *Client) Request(ctx context.Context, req ServiceRequest) (ServiceResponse, error) {
	return ch.channel.Request(ctx, req)
}

// Open opens a secure channel to the server and creates a session.
func (ch *Client) open(ctx context.Context) error {
	if err := ch.channel.Open(ctx); err != nil {
		return err
	}

	var localNonce, localCertificate, remoteNonce []byte
	localNonce = getNextNonce(nonceLength)
	localCertificate = ch.channel.localCertificate

	var createSessionRequest = &CreateSessionRequest{
		ClientDescription:       ch.localDescription,
		EndpointURL:             ch.remoteEndpoint.EndpointURL,
		SessionName:             ch.sessionName,
		ClientNonce:             ByteString(localNonce),
		ClientCertificate:       ByteString(localCertificate),
		RequestedSessionTimeout: ch.sessionTimeout,
		MaxResponseMessageSize:  defaultMaxMessageSize,
	}

	createSessionResponse, err := ch.createSession(ctx, createSessionRequest)
	if err != nil {
		return err
	}
	ch.sessionID = createSessionResponse.SessionID
	ch.channel.SetAuthenticationToken(createSessionResponse.AuthenticationToken)
	remoteNonce = []byte(createSessionResponse.ServerNonce)

	// verify the server's certificate is the same as the certificate from the selected endpoint.
	if ch.remoteEndpoint.ServerCertificate != "" && ch.remoteEndpoint.ServerCertificate != createSessionResponse.ServerCertificate {
		return BadCertificateInvalid
	}

	// verify the server's signature.
	switch ch.remoteEndpoint.SecurityPolicyURI {
	case SecurityPolicyURIBasic128Rsa15, SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(ch.channel.remotePublicKey, crypto.SHA1, hashed, []byte(createSessionResponse.ServerSignature.Signature))
		if err != nil {
			return BadApplicationSignatureInvalid
		}

	case SecurityPolicyURIBasic256Sha256, SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(ch.channel.remotePublicKey, crypto.SHA256, hashed, []byte(createSessionResponse.ServerSignature.Signature))
		if err != nil {
			return BadApplicationSignatureInvalid
		}

	case SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPSS(ch.channel.remotePublicKey, crypto.SHA256, hashed, []byte(createSessionResponse.ServerSignature.Signature), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return BadApplicationSignatureInvalid
		}

	}

	// create client signature
	var clientSignature *SignatureData
	switch ch.remoteEndpoint.SecurityPolicyURI {
	case SecurityPolicyURIBasic128Rsa15, SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, ch.channel.localPrivateKey, crypto.SHA1, hashed)
		if err != nil {
			return err
		}
		clientSignature = &SignatureData{
			Signature: ByteString(signature),
			Algorithm: RsaSha1Signature,
		}

	case SecurityPolicyURIBasic256Sha256, SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, ch.channel.localPrivateKey, crypto.SHA256, hashed)
		if err != nil {
			return err
		}
		clientSignature = &SignatureData{
			Signature: ByteString(signature),
			Algorithm: RsaSha256Signature,
		}

	case SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPSS(rand.Reader, ch.channel.localPrivateKey, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return err
		}
		clientSignature = &SignatureData{
			Signature: ByteString(signature),
			Algorithm: RsaPssSha256Signature,
		}

	default:
		clientSignature = &SignatureData{}
	}

	// supported UserIdentityToken types are AnonymousIdentityToken, UserNameIdentityToken, IssuedIdentityToken, X509IdentityToken
	var identityToken interface{}
	var identityTokenSignature *SignatureData
	switch ui := ch.userIdentity.(type) {

	case *IssuedIdentity:
		var tokenPolicy *UserTokenPolicy
		for _, t := range ch.remoteEndpoint.UserIdentityTokens {
			if t.TokenType == UserTokenTypeIssuedToken {
				tokenPolicy = t
				break
			}
		}
		if tokenPolicy == nil {
			return BadIdentityTokenRejected
		}

		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.remoteEndpoint.SecurityPolicyURI
		}

		switch secPolicyURI {
		case SecurityPolicyURIBasic128Rsa15:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(ui.TokenData)+len(remoteNonce)))
			plainBuf.Write([]byte(ui.TokenData))
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-11)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publickey, plainText)
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &IssuedIdentityToken{
				TokenData:           ByteString(cipherBytes),
				EncryptionAlgorithm: RsaV15KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		case SecurityPolicyURIBasic256, SecurityPolicyURIBasic256Sha256, SecurityPolicyURIAes128Sha256RsaOaep:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(ui.TokenData)+len(remoteNonce)))
			plainBuf.Write([]byte(ui.TokenData))
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-42)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				cipherText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publickey, plainText, []byte{})
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &IssuedIdentityToken{
				TokenData:           ByteString(cipherBytes),
				EncryptionAlgorithm: RsaOaepKeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		case SecurityPolicyURIAes256Sha256RsaPss:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(ui.TokenData)+len(remoteNonce)))
			plainBuf.Write([]byte(ui.TokenData))
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-66)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publickey, plainText, []byte{})
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &IssuedIdentityToken{
				TokenData:           ByteString(cipherBytes),
				EncryptionAlgorithm: RsaOaepSha256KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		default:
			identityToken = &IssuedIdentityToken{
				TokenData:           ui.TokenData,
				EncryptionAlgorithm: "",
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}
		}

	case *X509Identity:
		var tokenPolicy *UserTokenPolicy
		for _, t := range ch.remoteEndpoint.UserIdentityTokens {
			if t.TokenType == UserTokenTypeCertificate {
				tokenPolicy = t
				break
			}
		}
		if tokenPolicy == nil {
			return BadIdentityTokenRejected
		}

		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.remoteEndpoint.SecurityPolicyURI
		}

		switch secPolicyURI {
		case SecurityPolicyURIBasic128Rsa15, SecurityPolicyURIBasic256:
			hash := crypto.SHA1.New()
			hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPKCS1v15(rand.Reader, ui.Key, crypto.SHA1, hashed)
			if err != nil {
				return err
			}
			identityToken = &X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{
				Signature: ByteString(signature),
				Algorithm: RsaSha1Signature,
			}

		case SecurityPolicyURIBasic256Sha256, SecurityPolicyURIAes128Sha256RsaOaep:
			hash := crypto.SHA256.New()
			hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPKCS1v15(rand.Reader, ui.Key, crypto.SHA256, hashed)
			if err != nil {
				return err
			}
			identityToken = &X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{
				Signature: ByteString(signature),
				Algorithm: RsaSha256Signature,
			}

		case SecurityPolicyURIAes256Sha256RsaPss:
			hash := crypto.SHA256.New()
			hash.Write([]byte(ch.remoteEndpoint.ServerCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPSS(rand.Reader, ui.Key, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				return err
			}
			identityToken = &X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{
				Signature: ByteString(signature),
				Algorithm: RsaPssSha256Signature,
			}

		default:
			identityToken = &X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}
		}

	case *UserNameIdentity:
		var tokenPolicy *UserTokenPolicy
		for _, t := range ch.remoteEndpoint.UserIdentityTokens {
			if t.TokenType == UserTokenTypeUserName {
				tokenPolicy = t
				break
			}
		}
		if tokenPolicy == nil {
			return BadIdentityTokenRejected
		}

		passwordBytes := []byte(ui.Password)
		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.remoteEndpoint.SecurityPolicyURI
		}

		switch secPolicyURI {
		case SecurityPolicyURIBasic128Rsa15:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(passwordBytes)+len(remoteNonce)))
			plainBuf.Write(passwordBytes)
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-11)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				// encrypt with remote public key.
				cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publickey, plainText)
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            ByteString(cipherBytes),
				EncryptionAlgorithm: RsaV15KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		case SecurityPolicyURIBasic256, SecurityPolicyURIBasic256Sha256, SecurityPolicyURIAes128Sha256RsaOaep:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(passwordBytes)+len(remoteNonce)))
			plainBuf.Write(passwordBytes)
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-42)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				// encrypt with remote public key.
				cipherText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publickey, plainText, []byte{})
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            ByteString(cipherBytes),
				EncryptionAlgorithm: RsaOaepKeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		case SecurityPolicyURIAes256Sha256RsaPss:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return BadIdentityTokenRejected
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			binary.Write(plainBuf, binary.LittleEndian, uint32(len(passwordBytes)+len(remoteNonce)))
			plainBuf.Write(passwordBytes)
			plainBuf.Write(remoteNonce)
			plainText := make([]byte, publickey.Size()-66)
			for plainBuf.Len() > 0 {
				plainBuf.Read(plainText)
				// encrypt with remote public key.
				cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publickey, plainText, []byte{})
				if err != nil {
					return err
				}
				cipherBuf.Write(cipherText)
			}
			cipherBytes := make([]byte, cipherBuf.Len())
			cipherBuf.Read(cipherBytes)
			plainBuf.Reset()
			cipherBuf.Reset()

			identityToken = &UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            ByteString(cipherBytes),
				EncryptionAlgorithm: RsaOaepSha256KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}

		default:
			identityToken = &UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            ByteString(passwordBytes),
				EncryptionAlgorithm: "",
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = &SignatureData{}
		}

	default:
		var tokenPolicy *UserTokenPolicy
		for _, t := range ch.remoteEndpoint.UserIdentityTokens {
			if t.TokenType == UserTokenTypeAnonymous {
				tokenPolicy = t
				break
			}
		}
		if tokenPolicy == nil {
			return BadIdentityTokenRejected
		}

		identityToken = &AnonymousIdentityToken{PolicyID: tokenPolicy.PolicyID}
		identityTokenSignature = &SignatureData{}
	}

	// save for re-connect (instead of remote nonce)
	ch.clientSignature = clientSignature
	ch.identityToken = identityToken
	ch.identityTokenSignature = identityTokenSignature

	activateSessionRequest := &ActivateSessionRequest{
		ClientSignature:    ch.clientSignature,
		LocaleIDs:          []string{"en"},
		UserIdentityToken:  ch.identityToken,
		UserTokenSignature: ch.identityTokenSignature,
	}
	activateSessionResponse, err := ch.activateSession(ctx, activateSessionRequest)
	if err != nil {
		return err
	}
	remoteNonce = []byte(activateSessionResponse.ServerNonce)

	// fetch namespace array, etc.
	var readRequest = &ReadRequest{
		NodesToRead: []*ReadValueID{
			{
				NodeID:      VariableIDServerNamespaceArray,
				AttributeID: AttributeIDValue,
			},
			{
				NodeID:      VariableIDServerServerArray,
				AttributeID: AttributeIDValue,
			},
		},
	}
	readResponse, err := ch.Read(ctx, readRequest)
	if err != nil {
		return err
	}
	if len(readResponse.Results) == 2 {
		if readResponse.Results[0].StatusCode().IsGood() {
			value := readResponse.Results[0].Value().([]string)
			ch.channel.SetNamespaceURIs(value)
		}

		if readResponse.Results[1].StatusCode().IsGood() {
			value := readResponse.Results[1].Value().([]string)
			ch.channel.SetServerURIs(value)
		}
	}
	return nil
}

// Close closes the session and secure channel.
func (ch *Client) Close(ctx context.Context) error {
	var request = &CloseSessionRequest{
		DeleteSubscriptions: true,
	}
	_, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	// TODO: WaitGroup?
	return ch.channel.Close(ctx)
}

// Abort closes the client abruptly.
func (ch *Client) Abort(ctx context.Context) error {
	return ch.channel.Abort(ctx)
}
