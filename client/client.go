// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"sort"

	"github.com/awcullen/opcua"

	"github.com/djherbis/buffer"
)

// Dial returns a secure channel to the OPC UA server with the given URL and options.
func Dial(ctx context.Context, endpointURL string, opts ...Option) (c *Client, err error) {

	cli := &Client{
		userIdentity:      opcua.AnonymousIdentity{},
		applicationName:   "awcullen/opcua",
		sessionTimeout:    defaultSessionTimeout,
		securityPolicyURI: opcua.SecurityPolicyURIBestAvailable,
		timeoutHint:       defaultTimeoutHint,
		diagnosticsHint:   defaultDiagnosticsHint,
		tokenLifetime:     defaultTokenRequestedLifetime,
		connectTimeout:    defaultConnectTimeout,
		trace:             false,
	}

	// apply each option to the default
	for _, opt := range opts {
		if err := opt(cli); err != nil {
			return nil, err
		}
	}

	// get endpoints from discovery url
	req := &opcua.GetEndpointsRequest{
		EndpointURL: endpointURL,
		ProfileURIs: []string{opcua.TransportProfileURIUaTcpTransport},
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
	securityPolicyURI := cli.securityPolicyURI
	if securityPolicyURI == opcua.SecurityPolicyURIBestAvailable && len(cli.applicationCertificate.Certificate) == 0 {
		securityPolicyURI = opcua.SecurityPolicyURINone
	}

	// select first endpoint with matching policy uri.
	var selectedEndpoint *opcua.EndpointDescription
	for _, e := range orderedEndpoints {
		// filter out unsupported policy uri
		switch e.SecurityPolicyURI {
		case opcua.SecurityPolicyURINone, opcua.SecurityPolicyURIBasic128Rsa15,
			opcua.SecurityPolicyURIBasic256, opcua.SecurityPolicyURIBasic256Sha256,
			opcua.SecurityPolicyURIAes128Sha256RsaOaep, opcua.SecurityPolicyURIAes256Sha256RsaPss:
		default:
			continue
		}
		// if policy uri is empty string, select the first endpoint
		if securityPolicyURI == "" {
			selectedEndpoint = &e
			break
		}
		// if policy uri is a match
		if e.SecurityPolicyURI == securityPolicyURI {
			selectedEndpoint = &e
			break
		}
	}
	if selectedEndpoint == nil {
		return nil, opcua.BadUnexpectedError
	}
	cli.endpointURL = selectedEndpoint.EndpointURL
	cli.securityPolicyURI = selectedEndpoint.SecurityPolicyURI
	cli.securityMode = selectedEndpoint.SecurityMode
	cli.serverCertificate = selectedEndpoint.ServerCertificate
	cli.userTokenPolicies = selectedEndpoint.UserIdentityTokens

	cli.localDescription = opcua.ApplicationDescription{
		ApplicationName: opcua.LocalizedText{Text: cli.applicationName},
		ApplicationType: opcua.ApplicationTypeClient,
	}

	var localCertificate []byte
	var localPrivateKey *rsa.PrivateKey

	if len(cli.applicationCertificate.Certificate) > 0 {
		localCertificate = cli.applicationCertificate.Certificate[0]
		localPrivateKey = cli.applicationCertificate.PrivateKey.(*rsa.PrivateKey)
		crt, _ := x509.ParseCertificate(localCertificate)
		// if cert has URI then update local description
		if len(crt.URIs) > 0 {
			cli.localDescription.ApplicationURI = crt.URIs[0].String()
		}
	}

	cli.channel = newClientSecureChannel(
		cli.localDescription,
		localCertificate,
		localPrivateKey,
		cli.endpointURL,
		cli.securityPolicyURI,
		cli.securityMode,
		[]byte(cli.serverCertificate),
		cli.connectTimeout,
		cli.applicationCertificate,
		cli.trustedCertsFile,
		cli.suppressHostNameInvalid,
		cli.suppressCertificateExpired,
		cli.suppressCertificateChainIncomplete,
		cli.timeoutHint,
		cli.diagnosticsHint,
		cli.tokenLifetime,
		cli.trace)

	// open session and read the namespace table
	if err := cli.open(ctx); err != nil {
		cli.Abort(ctx)
		return nil, err
	}

	return cli, nil
}

// Client for exchanging binary encoded requests and responses with an OPC UA server.
// Uses TCP with the binary security protocol UA-SecureConversation 1.0 and the binary message encoding UA-Binary 1.0.
type Client struct {
	channel                            *clientSecureChannel
	localDescription                   opcua.ApplicationDescription
	endpointURL                        string
	securityPolicyURI                  string
	securityMode                       opcua.MessageSecurityMode
	serverCertificate                  opcua.ByteString
	userTokenPolicies                  []opcua.UserTokenPolicy
	userIdentity                       interface{}
	sessionID                          opcua.NodeID
	sessionName                        string
	applicationName                    string
	sessionTimeout                     float64
	clientSignature                    opcua.SignatureData
	identityToken                      interface{}
	identityTokenSignature             opcua.SignatureData
	timeoutHint                        uint32
	diagnosticsHint                    uint32
	tokenLifetime                      uint32
	applicationCertificate             tls.Certificate
	trustedCertsFile                   string
	suppressHostNameInvalid            bool
	suppressCertificateExpired         bool
	suppressCertificateChainIncomplete bool
	connectTimeout                     int64
	trace                              bool
}

// EndpointURL gets the EndpointURL of the server.
func (ch *Client) EndpointURL() string {
	return ch.endpointURL
}

// SecurityPolicyURI gets the SecurityPolicyURI of the secure channel.
func (ch *Client) SecurityPolicyURI() string {
	return ch.securityPolicyURI
}

// SecurityMode gets the MessageSecurityMode of the secure channel.
func (ch *Client) SecurityMode() opcua.MessageSecurityMode {
	return ch.securityMode
}

// SessionID gets the id of the current session.
func (ch *Client) SessionID() opcua.NodeID {
	return ch.sessionID
}

// Request sends a service request to the server and returns the response.
func (ch *Client) request(ctx context.Context, req opcua.ServiceRequest) (opcua.ServiceResponse, error) {
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

	var createSessionRequest = &opcua.CreateSessionRequest{
		ClientDescription:       ch.localDescription,
		EndpointURL:             ch.endpointURL,
		SessionName:             ch.sessionName,
		ClientNonce:             opcua.ByteString(localNonce),
		ClientCertificate:       opcua.ByteString(localCertificate),
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
	if ch.serverCertificate != "" && ch.serverCertificate != createSessionResponse.ServerCertificate {
		return opcua.BadCertificateInvalid
	}

	// verify the server's signature.
	switch ch.securityPolicyURI {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(ch.channel.remotePublicKey, crypto.SHA1, hashed, []byte(createSessionResponse.ServerSignature.Signature))
		if err != nil {
			return opcua.BadApplicationSignatureInvalid
		}

	case opcua.SecurityPolicyURIBasic256Sha256, opcua.SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPKCS1v15(ch.channel.remotePublicKey, crypto.SHA256, hashed, []byte(createSessionResponse.ServerSignature.Signature))
		if err != nil {
			return opcua.BadApplicationSignatureInvalid
		}

	case opcua.SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write(localCertificate)
		hash.Write(localNonce)
		hashed := hash.Sum(nil)
		err := rsa.VerifyPSS(ch.channel.remotePublicKey, crypto.SHA256, hashed, []byte(createSessionResponse.ServerSignature.Signature), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return opcua.BadApplicationSignatureInvalid
		}

	}

	// create client signature
	var clientSignature opcua.SignatureData
	switch ch.securityPolicyURI {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write([]byte(ch.serverCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, ch.channel.localPrivateKey, crypto.SHA1, hashed)
		if err != nil {
			return err
		}
		clientSignature = opcua.SignatureData{
			Signature: opcua.ByteString(signature),
			Algorithm: opcua.RsaSha1Signature,
		}

	case opcua.SecurityPolicyURIBasic256Sha256, opcua.SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write([]byte(ch.serverCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, ch.channel.localPrivateKey, crypto.SHA256, hashed)
		if err != nil {
			return err
		}
		clientSignature = opcua.SignatureData{
			Signature: opcua.ByteString(signature),
			Algorithm: opcua.RsaSha256Signature,
		}

	case opcua.SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write([]byte(ch.serverCertificate))
		hash.Write(remoteNonce)
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPSS(rand.Reader, ch.channel.localPrivateKey, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return err
		}
		clientSignature = opcua.SignatureData{
			Signature: opcua.ByteString(signature),
			Algorithm: opcua.RsaPssSha256Signature,
		}

	default:
		clientSignature = opcua.SignatureData{}
	}

	// supported UserIdentityToken types are AnonymousIdentityToken, UserNameIdentityToken, IssuedIdentityToken, X509IdentityToken
	var identityToken interface{}
	var identityTokenSignature opcua.SignatureData
	switch ui := ch.userIdentity.(type) {

	case opcua.IssuedIdentity:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.userTokenPolicies {
			if t.TokenType == opcua.UserTokenTypeIssuedToken {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			return opcua.BadIdentityTokenRejected
		}

		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.securityPolicyURI
		}

		switch secPolicyURI {
		case opcua.SecurityPolicyURIBasic128Rsa15:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.IssuedIdentityToken{
				TokenData:           opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaV15KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		case opcua.SecurityPolicyURIBasic256, opcua.SecurityPolicyURIBasic256Sha256, opcua.SecurityPolicyURIAes128Sha256RsaOaep:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.IssuedIdentityToken{
				TokenData:           opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaOaepKeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		case opcua.SecurityPolicyURIAes256Sha256RsaPss:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.IssuedIdentityToken{
				TokenData:           opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaOaepSha256KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		default:
			identityToken = opcua.IssuedIdentityToken{
				TokenData:           ui.TokenData,
				EncryptionAlgorithm: "",
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}
		}

	case opcua.X509Identity:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.userTokenPolicies {
			if t.TokenType == opcua.UserTokenTypeCertificate {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			return opcua.BadIdentityTokenRejected
		}

		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.securityPolicyURI
		}

		switch secPolicyURI {
		case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
			hash := crypto.SHA1.New()
			hash.Write([]byte(ch.serverCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPKCS1v15(rand.Reader, ui.Key, crypto.SHA1, hashed)
			if err != nil {
				return err
			}
			identityToken = opcua.X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{
				Signature: opcua.ByteString(signature),
				Algorithm: opcua.RsaSha1Signature,
			}

		case opcua.SecurityPolicyURIBasic256Sha256, opcua.SecurityPolicyURIAes128Sha256RsaOaep:
			hash := crypto.SHA256.New()
			hash.Write([]byte(ch.serverCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPKCS1v15(rand.Reader, ui.Key, crypto.SHA256, hashed)
			if err != nil {
				return err
			}
			identityToken = opcua.X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{
				Signature: opcua.ByteString(signature),
				Algorithm: opcua.RsaSha256Signature,
			}

		case opcua.SecurityPolicyURIAes256Sha256RsaPss:
			hash := crypto.SHA256.New()
			hash.Write([]byte(ch.serverCertificate))
			hash.Write(remoteNonce)
			hashed := hash.Sum(nil)
			signature, err := rsa.SignPSS(rand.Reader, ui.Key, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				return err
			}
			identityToken = opcua.X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{
				Signature: opcua.ByteString(signature),
				Algorithm: opcua.RsaPssSha256Signature,
			}

		default:
			identityToken = opcua.X509IdentityToken{
				CertificateData: ui.Certificate,
				PolicyID:        tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}
		}

	case opcua.UserNameIdentity:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.userTokenPolicies {
			if t.TokenType == opcua.UserTokenTypeUserName {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			return opcua.BadIdentityTokenRejected
		}

		passwordBytes := []byte(ui.Password)
		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.securityPolicyURI
		}

		switch secPolicyURI {
		case opcua.SecurityPolicyURIBasic128Rsa15:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaV15KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		case opcua.SecurityPolicyURIBasic256, opcua.SecurityPolicyURIBasic256Sha256, opcua.SecurityPolicyURIAes128Sha256RsaOaep:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaOaepKeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		case opcua.SecurityPolicyURIAes256Sha256RsaPss:
			publickey := ch.channel.remotePublicKey
			if publickey == nil {
				return opcua.BadIdentityTokenRejected
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

			identityToken = opcua.UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            opcua.ByteString(cipherBytes),
				EncryptionAlgorithm: opcua.RsaOaepSha256KeyWrap,
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}

		default:
			identityToken = opcua.UserNameIdentityToken{
				UserName:            ui.UserName,
				Password:            opcua.ByteString(passwordBytes),
				EncryptionAlgorithm: "",
				PolicyID:            tokenPolicy.PolicyID,
			}
			identityTokenSignature = opcua.SignatureData{}
		}

	default:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.userTokenPolicies {
			if t.TokenType == opcua.UserTokenTypeAnonymous {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			return opcua.BadIdentityTokenRejected
		}

		identityToken = opcua.AnonymousIdentityToken{PolicyID: tokenPolicy.PolicyID}
		identityTokenSignature = opcua.SignatureData{}
	}

	// save for re-connect (instead of remote nonce)
	ch.clientSignature = clientSignature
	ch.identityToken = identityToken
	ch.identityTokenSignature = identityTokenSignature

	activateSessionRequest := &opcua.ActivateSessionRequest{
		ClientSignature:    ch.clientSignature,
		LocaleIDs:          []string{"en"},
		UserIdentityToken:  identityToken,
		UserTokenSignature: ch.identityTokenSignature,
	}
	activateSessionResponse, err := ch.activateSession(ctx, activateSessionRequest)
	if err != nil {
		return err
	}
	_ = []byte(activateSessionResponse.ServerNonce)

	// fetch namespace array, etc.
	var readRequest = &opcua.ReadRequest{
		NodesToRead: []opcua.ReadValueID{
			{
				NodeID:      opcua.VariableIDServerNamespaceArray,
				AttributeID: opcua.AttributeIDValue,
			},
			{
				NodeID:      opcua.VariableIDServerServerArray,
				AttributeID: opcua.AttributeIDValue,
			},
		},
	}
	readResponse, err := ch.Read(ctx, readRequest)
	if err != nil {
		return err
	}
	if len(readResponse.Results) == 2 {
		if readResponse.Results[0].StatusCode.IsGood() {
			value := readResponse.Results[0].Value.([]string)
			ch.channel.SetNamespaceURIs(value)
		}

		if readResponse.Results[1].StatusCode.IsGood() {
			value := readResponse.Results[1].Value.([]string)
			ch.channel.SetServerURIs(value)
		}
	}
	return nil
}

// Close closes the session and secure channel.
func (ch *Client) Close(ctx context.Context) error {
	var request = &opcua.CloseSessionRequest{
		DeleteSubscriptions: true,
	}
	_, err := ch.closeSession(ctx, request)
	if err != nil {
		return err
	}
	return ch.channel.Close(ctx)
}

// Abort closes the client abruptly.
func (ch *Client) Abort(ctx context.Context) error {
	return ch.channel.Abort(ctx)
}
