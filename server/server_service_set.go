// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/djherbis/buffer"
	"github.com/google/uuid"
)

// FindServers returns the Servers known to a Server or Discovery Server.
func (srv *Server) findServers(ch *serverSecureChannel, requestid uint32, req *ua.FindServersRequest) error {
	srvs := make([]ua.ApplicationDescription, 0, 1)
	for _, s := range []ua.ApplicationDescription{srv.LocalDescription()} {
		if len(req.ServerURIs) > 0 {
			for _, su := range req.ServerURIs {
				if s.ApplicationURI == su {
					srvs = append(srvs, s)
					break
				}
			}
		} else {
			srvs = append(srvs, s)
		}
	}
	ch.Write(
		&ua.FindServersResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Servers: srvs,
		},
		requestid,
	)
	return nil
}

// GetEndpoints returns the endpoint descriptions supported by the server.
func (srv *Server) getEndpoints(ch *serverSecureChannel, requestid uint32, req *ua.GetEndpointsRequest) error {
	eps := make([]ua.EndpointDescription, 0, len(srv.Endpoints()))
	for _, ep := range srv.Endpoints() {
		if len(req.ProfileURIs) > 0 {
			for _, pu := range req.ProfileURIs {
				if ep.TransportProfileURI == pu {
					eps = append(eps, ep)
					break
				}
			}
		} else {
			eps = append(eps, ep)
		}
	}
	ch.Write(
		&ua.GetEndpointsResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Endpoints: eps,
		},
		requestid,
	)
	return nil
}

// createSession creates a session.
func (srv *Server) handleCreateSession(ch *serverSecureChannel, requestid uint32, req *ua.CreateSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// check endpointurl hostname matches one of the certificate hostnames
	valid := false
	if crt, err := x509.ParseCertificate(srv.LocalCertificate()); err == nil {
		if remoteURL, err := url.Parse(req.EndpointURL); err == nil {
			hostname := remoteURL.Host
			i := strings.Index(hostname, ":")
			if i != -1 {
				hostname = hostname[:i]
			}
			if err := crt.VerifyHostname(hostname); err == nil {
				valid = true
			}
		}
	}
	if !valid {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadCertificateHostNameInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	// check nonce
	switch ch.SecurityPolicyURI() {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.SecurityPolicyURIAes256Sha256RsaPss:

		// check client application uri matches one of the client certificate's san.
		valid := false
		if appuri := req.ClientDescription.ApplicationURI; appuri != "" {
			if crt, err := x509.ParseCertificate([]byte(req.ClientCertificate)); err == nil {
				for _, crturi := range crt.URIs {
					if crturi.String() == appuri {
						valid = true
						break
					}
				}
			}
		}
		if !valid {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadCertificateURIInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		if len(req.ClientNonce) < int(nonceLength) {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadNonceInvalid,
					},
				},
				requestid,
			)
			return nil
		}
	default:
	}
	// create server signature
	var serverSignature ua.SignatureData
	switch ch.SecurityPolicyURI() {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write([]byte(req.ClientCertificate))
		hash.Write([]byte(req.ClientNonce))
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, srv.localPrivateKey, crypto.SHA1, hashed)
		if err != nil {
			return err
		}
		serverSignature = ua.SignatureData{
			Signature: ua.ByteString(signature),
			Algorithm: ua.RsaSha1Signature,
		}

	case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write([]byte(req.ClientCertificate))
		hash.Write([]byte(req.ClientNonce))
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, srv.localPrivateKey, crypto.SHA256, hashed)
		if err != nil {
			return err
		}
		serverSignature = ua.SignatureData{
			Signature: ua.ByteString(signature),
			Algorithm: ua.RsaSha256Signature,
		}

	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write([]byte(req.ClientCertificate))
		hash.Write([]byte(req.ClientNonce))
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPSS(rand.Reader, srv.localPrivateKey, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return err
		}
		serverSignature = ua.SignatureData{
			Signature: ua.ByteString(signature),
			Algorithm: ua.RsaPssSha256Signature,
		}

	default:
		serverSignature = ua.SignatureData{}
	}

	sessionName := req.SessionName
	if len(sessionName) == 0 {
		sessionName = req.ClientDescription.ApplicationURI
	}

	session := NewSession(
		srv,
		ua.NewNodeIDOpaque(1, ua.ByteString(getNextNonce(15))),
		sessionName,
		ua.NewNodeIDOpaque(0, ua.ByteString(getNextNonce(nonceLength))),
		ua.ByteString(getNextNonce(nonceLength)),
		(time.Duration(req.RequestedSessionTimeout) * time.Millisecond),
		req.ClientDescription,
		req.ServerURI,
		req.EndpointURL,
		req.MaxResponseMessageSize,
	)
	err := srv.SessionManager().Add(session)
	if err != nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManySessions,
				},
			},
			requestid,
		)
		return nil
	}
	// log.Printf("Created session '%s'.\n", req.SessionName)

	ch.Write(
		&ua.CreateSessionResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			SessionID:                  session.sessionId,
			AuthenticationToken:        session.authenticationToken,
			RevisedSessionTimeout:      req.RequestedSessionTimeout,
			ServerNonce:                session.sessionNonce,
			ServerCertificate:          ua.ByteString(srv.LocalCertificate()),
			ServerEndpoints:            srv.Endpoints(),
			ServerSoftwareCertificates: nil,
			ServerSignature:            serverSignature,
			MaxRequestMessageSize:      0,
		},
		requestid,
	)
	return nil
}

// handleActivateSession activates a session.
func (srv *Server) handleActivateSession(ch *serverSecureChannel, requestid uint32, req *ua.ActivateSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	m := srv.sessionManager
	session, ok := m.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	// verify the client's signature.
	var err error
	switch ch.SecurityPolicyURI() {
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write(srv.LocalCertificate())
		hash.Write([]byte(session.SessionNonce()))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPKCS1v15(ch.RemotePublicKey(), crypto.SHA1, hashed, []byte(req.ClientSignature.Signature))

	case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
		hash := crypto.SHA256.New()
		hash.Write(srv.LocalCertificate())
		hash.Write([]byte(session.SessionNonce()))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPKCS1v15(ch.RemotePublicKey(), crypto.SHA256, hashed, []byte(req.ClientSignature.Signature))

	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		hash := crypto.SHA256.New()
		hash.Write(srv.LocalCertificate())
		hash.Write([]byte(session.SessionNonce()))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPSS(ch.RemotePublicKey(), crypto.SHA256, hashed, []byte(req.ClientSignature.Signature), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	if err != nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadApplicationSignatureInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	// validate identity and store
	var userIdentity interface{}
	switch userIdentityToken := req.UserIdentityToken.(type) {
	case ua.IssuedIdentityToken:
		var tokenPolicy *ua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeCertificate && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		// TODO: validate IssuedIdentity
		userIdentity = ua.IssuedIdentity{TokenData: userIdentityToken.TokenData}

	case ua.X509IdentityToken:
		var tokenPolicy *ua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeCertificate && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.SecurityPolicyURI()
		}
		userCert, err := x509.ParseCertificate([]byte(userIdentityToken.CertificateData))
		if err != nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		userKey, ok := userCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}

		switch secPolicyURI {
		case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
			hash := crypto.SHA1.New()
			hash.Write(srv.LocalCertificate())
			hash.Write([]byte(session.SessionNonce()))
			hashed := hash.Sum(nil)
			err = rsa.VerifyPKCS1v15(userKey, crypto.SHA1, hashed, []byte(req.UserTokenSignature.Signature))

		case ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
			hash := crypto.SHA256.New()
			hash.Write(srv.LocalCertificate())
			hash.Write([]byte(session.SessionNonce()))
			hashed := hash.Sum(nil)
			err = rsa.VerifyPKCS1v15(userKey, crypto.SHA256, hashed, []byte(req.UserTokenSignature.Signature))

		case ua.SecurityPolicyURIAes256Sha256RsaPss:
			hash := crypto.SHA256.New()
			hash.Write(srv.LocalCertificate())
			hash.Write([]byte(session.SessionNonce()))
			hashed := hash.Sum(nil)
			err = rsa.VerifyPSS(userKey, crypto.SHA256, hashed, []byte(req.UserTokenSignature.Signature), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenRejected,
					},
				},
				requestid,
			)
			return nil
		}
		userIdentity = ua.X509Identity{Certificate: userIdentityToken.CertificateData}

	case ua.UserNameIdentityToken:
		var tokenPolicy *ua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeUserName && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		if userIdentityToken.UserName == "" {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		cipherBytes := []byte(userIdentityToken.Password)
		secPolicyURI := tokenPolicy.SecurityPolicyURI
		if secPolicyURI == "" {
			secPolicyURI = ch.LocalEndpoint().SecurityPolicyURI
		}

		switch secPolicyURI {
		case ua.SecurityPolicyURIBasic128Rsa15:
			if userIdentityToken.EncryptionAlgorithm != ua.RsaV15KeyWrap {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenInvalid,
						},
					},
					requestid,
				)
				return nil
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf.Write(cipherBytes)
			cipherText := make([]byte, int32(len(srv.localPrivateKey.D.Bytes())))
			for cipherBuf.Len() > 0 {
				cipherBuf.Read(cipherText)
				// decrypt with local private key.
				plainText, err := rsa.DecryptPKCS1v15(rand.Reader, srv.localPrivateKey, cipherText)
				if err != nil {
					return err
				}
				plainBuf.Write(plainText)
			}
			plainLength := uint32(0)
			if plainBuf.Len() > 0 {
				binary.Read(plainBuf, binary.LittleEndian, &plainLength)
			}
			if plainLength < 32 || plainLength > 96 {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenRejected,
						},
					},
					requestid,
				)
				return nil
			}
			passwordBytes := make([]byte, plainLength-32)
			plainBuf.Read(passwordBytes)
			cipherBuf.Reset()
			plainBuf.Reset()
			userIdentity = ua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(passwordBytes)}

		case ua.SecurityPolicyURIBasic256, ua.SecurityPolicyURIBasic256Sha256, ua.SecurityPolicyURIAes128Sha256RsaOaep:
			if userIdentityToken.EncryptionAlgorithm != ua.RsaOaepKeyWrap {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenInvalid,
						},
					},
					requestid,
				)
				return nil
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf.Write(cipherBytes)
			cipherText := make([]byte, int32(len(srv.localPrivateKey.D.Bytes())))
			for cipherBuf.Len() > 0 {
				cipherBuf.Read(cipherText)
				// decrypt with local private key.
				plainText, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, srv.localPrivateKey, cipherText, []byte{})
				if err != nil {
					return err
				}
				plainBuf.Write(plainText)
			}
			plainLength := uint32(0)
			if plainBuf.Len() > 0 {
				binary.Read(plainBuf, binary.LittleEndian, &plainLength)
			}
			if plainLength < 32 || plainLength > 96 {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenRejected,
						},
					},
					requestid,
				)
				return nil
			}
			passwordBytes := make([]byte, plainLength-32)
			plainBuf.Read(passwordBytes)
			cipherBuf.Reset()
			plainBuf.Reset()
			userIdentity = ua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(passwordBytes)}

		case ua.SecurityPolicyURIAes256Sha256RsaPss:
			if userIdentityToken.EncryptionAlgorithm != ua.RsaOaepSha256KeyWrap {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenInvalid,
						},
					},
					requestid,
				)
				return nil
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf.Write(cipherBytes)
			cipherText := make([]byte, int32(len(srv.localPrivateKey.D.Bytes())))
			for cipherBuf.Len() > 0 {
				cipherBuf.Read(cipherText)
				// decrypt with local private key.
				plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, srv.localPrivateKey, cipherText, []byte{})
				if err != nil {
					return err
				}
				plainBuf.Write(plainText)
			}
			plainLength := uint32(0)
			if plainBuf.Len() > 0 {
				binary.Read(plainBuf, binary.LittleEndian, &plainLength)
			}
			if plainLength < 32 || plainLength > 96 {
				ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadIdentityTokenRejected,
						},
					},
					requestid,
				)
				return nil
			}
			passwordBytes := make([]byte, plainLength-32)
			plainBuf.Read(passwordBytes)
			cipherBuf.Reset()
			plainBuf.Reset()
			userIdentity = ua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(passwordBytes)}

		default:
			userIdentity = ua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(cipherBytes)}

		}

	case ua.AnonymousIdentityToken:
		var tokenPolicy *ua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeAnonymous && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		userIdentity = ua.AnonymousIdentity{}

	}

	// authenticate user
	switch id := userIdentity.(type) {
	case ua.AnonymousIdentity:
		if srv.allowAnonymousIdentity {
			err = nil
		} else {
			err = ua.BadUserAccessDenied
		}

	case ua.UserNameIdentity:
		if auth := srv.userNameIdentityAuthenticator; auth != nil {
			err = auth.AuthenticateUserNameIdentity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = ua.BadUserAccessDenied
		}

	case ua.X509Identity:
		if auth := srv.x509IdentityAuthenticator; auth != nil {
			err = auth.AuthenticateX509Identity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = ua.BadUserAccessDenied
		}

	case ua.IssuedIdentity:
		if auth := srv.issuedIdentityAuthenticator; auth != nil {
			err = auth.AuthenticateIssuedIdentity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = ua.BadUserAccessDenied
		}

	default:
		err = ua.BadUserAccessDenied

	}
	if err != nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadUserAccessDenied,
				},
			},
			requestid,
		)
		return nil
	}

	// get roles
	userRoles, err := srv.rolesProvider.GetRoles(userIdentity, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
	if err != nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadUserAccessDenied,
				},
			},
			requestid,
		)
		return nil
	}

	session.SetUserIdentity(userIdentity)
	session.SetUserRoles(userRoles)
	session.SetSessionNonce(ua.ByteString(getNextNonce(nonceLength)))
	session.SetSecureChannelId(ch.ChannelID())
	session.localeIds = req.LocaleIDs

	ch.Write(
		&ua.ActivateSessionResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			ServerNonce:     session.SessionNonce(),
			Results:         nil,
			DiagnosticInfos: nil,
		},
		requestid,
	)
	return nil
}

// closeSession closes a session.
func (srv *Server) handleCloseSession(ch *serverSecureChannel, requestid uint32, req *ua.CloseSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.sessionManager.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	// delete subscriptions if requested
	if req.DeleteSubscriptions {
		sm := srv.SubscriptionManager()
		for _, s := range sm.GetBySession(session) {
			sm.Delete(s)
			s.Delete()
		}
	}

	// delete session
	srv.sessionManager.Delete(session)

	// log.Printf("Deleted session '%s'.\n", session.SessionName())

	ch.Write(
		&ua.CloseSessionResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
		},
		requestid,
	)
	return nil
}

// handleCancel cancels a request.
func (srv *Server) handleCancel(ch *serverSecureChannel, requestid uint32, req *ua.CancelRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.sessionManager.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	ch.Write(
		&ua.CancelResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
		},
		requestid,
	)
	return nil
}

// AddNodes adds one or more Nodes into the AddressSpace hierarchy.
// AddReferences adds one or more References to one or more Nodes.
// DeleteNodes deletes one or more Nodes from the AddressSpace.
// DeleteReferences deletes one or more References of a Node.

func (srv *Server) handleBrowse(ch *serverSecureChannel, requestid uint32, req *ua.BrowseRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.browseCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.browseErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.browseErrorCount++
		session.errorCount++
		return nil
	}

	if req.View.ViewID != nil {
		m := srv.NamespaceManager()
		n, ok := m.FindNode(req.View.ViewID)
		if !ok {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadViewIDUnknown,
					},
				},
				requestid,
			)
			session.browseErrorCount++
			session.errorCount++
			return nil
		}
		if n.NodeClass() != ua.NodeClassView {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadViewIDUnknown,
					},
				},
				requestid,
			)
			session.browseErrorCount++
			session.errorCount++
			return nil
		}
	}

	l := len(req.NodesToBrowse)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.browseErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerBrowse) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.browseErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]ua.BrowseResult, l)
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			d := req.NodesToBrowse[i]
			if d.BrowseDirection < ua.BrowseDirectionForward || d.BrowseDirection > ua.BrowseDirectionBoth {
				results[i] = ua.BrowseResult{StatusCode: ua.BadBrowseDirectionInvalid}
				wg.Done()
				return
			}
			m := srv.NamespaceManager()
			node, ok := m.FindNode(d.NodeID)
			if !ok {
				results[i] = ua.BrowseResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp := node.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
				results[i] = ua.BrowseResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			both := d.BrowseDirection == ua.BrowseDirectionBoth
			isInverse := d.BrowseDirection == ua.BrowseDirectionInverse
			allTypes := d.ReferenceTypeID == nil
			allClasses := d.NodeClassMask == 0
			if !allTypes {
				rt, ok := m.FindNode(d.ReferenceTypeID)
				if !ok {
					results[i] = ua.BrowseResult{StatusCode: ua.BadReferenceTypeIDInvalid}
					wg.Done()
					return
				}
				if rt.NodeClass() != ua.NodeClassReferenceType {
					results[i] = ua.BrowseResult{StatusCode: ua.BadReferenceTypeIDInvalid}
					wg.Done()
					return
				}
			}
			refs := node.References()
			rds := make([]ua.ReferenceDescription, 0, len(refs))
			for _, r := range refs {
				if !(both || r.IsInverse == isInverse) {
					continue
				}
				if !(allTypes || d.ReferenceTypeID == r.ReferenceTypeID || (d.IncludeSubtypes && m.IsSubtype(r.ReferenceTypeID, d.ReferenceTypeID))) {
					continue
				}
				t, ok := m.FindNode(ua.ToNodeID(r.TargetID, srv.NamespaceUris()))
				if !ok {
					results[i] = ua.BrowseResult{StatusCode: ua.BadNodeIDUnknown}
					wg.Done()
					return
				}
				rp2 := t.UserRolePermissions(ctx)
				if !IsUserPermitted(rp2, ua.PermissionTypeBrowse) {
					continue
				}
				if !(allClasses || d.NodeClassMask&uint32(t.NodeClass()) != 0) {
					continue
				}
				var rt ua.NodeID
				if d.ResultMask&uint32(ua.BrowseResultMaskReferenceTypeID) != 0 {
					rt = r.ReferenceTypeID
				}
				fo := false
				if d.ResultMask&uint32(ua.BrowseResultMaskIsForward) != 0 {
					fo = !r.IsInverse
				}
				nc := ua.NodeClassUnspecified
				if d.ResultMask&uint32(ua.BrowseResultMaskNodeClass) != 0 {
					nc = t.NodeClass()
				}
				bn := ua.QualifiedName{}
				if d.ResultMask&uint32(ua.BrowseResultMaskBrowseName) != 0 {
					bn = t.BrowseName()
				}
				dn := ua.LocalizedText{}
				if d.ResultMask&uint32(ua.BrowseResultMaskDisplayName) != 0 {
					dn = t.DisplayName()
				}
				var td ua.ExpandedNodeID
				if d.ResultMask&uint32(ua.BrowseResultMaskTypeDefinition) != 0 {
					if nc := t.NodeClass(); nc == ua.NodeClassObject || nc == ua.NodeClassVariable {
						hasTypeDef := ua.ReferenceTypeIDHasTypeDefinition
						for _, tr := range t.References() {
							if hasTypeDef == tr.ReferenceTypeID {
								td = tr.TargetID
								break
							}
						}
					}
				}
				rds = append(rds, ua.ReferenceDescription{
					ReferenceTypeID: rt,
					IsForward:       fo,
					NodeID:          r.TargetID,
					BrowseName:      bn,
					DisplayName:     dn,
					NodeClass:       nc,
					TypeDefinition:  td,
				})
			}

			if max := int(req.RequestedMaxReferencesPerNode); max > 0 && len(rds) > max {
				cp, err := session.addBrowseContinuationPoint(rds[max:], max)
				if err != nil {
					results[i] = ua.BrowseResult{
						StatusCode: ua.BadNoContinuationPoints,
					}
					wg.Done()
					return
				}
				results[i] = ua.BrowseResult{
					ContinuationPoint: ua.ByteString(cp),
					References:        rds[:max],
				}
				wg.Done()
				return
			}

			results[i] = ua.BrowseResult{
				References: rds,
			}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.BrowseResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
				},
				Results: results,
			},
			requestid,
		)
	}()
	return nil
}

func (srv *Server) handleBrowseNext(ch *serverSecureChannel, requestid uint32, req *ua.BrowseNextRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.browseNextCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.browseNextErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.browseNextErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.ContinuationPoints)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.browseNextErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerBrowse) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.browseNextErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]ua.BrowseResult, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			cp := req.ContinuationPoints[i]
			if len(cp) == 0 {
				results[i] = ua.BrowseResult{
					StatusCode: ua.Good,
				}
				wg.Done()
				return
			}
			rds, max, ok := session.removeBrowseContinuationPoint([]byte(cp))
			if !ok {
				results[i] = ua.BrowseResult{
					StatusCode: ua.BadContinuationPointInvalid,
				}
				wg.Done()
				return
			}
			if req.ReleaseContinuationPoints {
				results[i] = ua.BrowseResult{
					StatusCode: 0,
				}
				wg.Done()
				return
			}
			if len(rds) > max {
				cp, err := session.addBrowseContinuationPoint(rds[max:], max)
				if err != nil {
					results[i] = ua.BrowseResult{
						StatusCode: ua.BadNoContinuationPoints,
					}
					wg.Done()
					return
				}
				results[i] = ua.BrowseResult{
					ContinuationPoint: ua.ByteString(cp),
					References:        rds[:max],
				}
				wg.Done()
				return
			}
			results[i] = ua.BrowseResult{
				References: rds,
			}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.BrowseNextResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				Results: results,
			},
			requestid,
		)
	}()
	return nil
}

func (srv *Server) handleTranslateBrowsePathsToNodeIds(ch *serverSecureChannel, requestid uint32, req *ua.TranslateBrowsePathsToNodeIDsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.translateBrowsePathsToNodeIdsCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.translateBrowsePathsToNodeIdsErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.translateBrowsePathsToNodeIdsErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.BrowsePaths)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.translateBrowsePathsToNodeIdsErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerTranslateBrowsePathsToNodeIds) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.translateBrowsePathsToNodeIdsErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]ua.BrowsePathResult, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			d := req.BrowsePaths[i]
			if len(d.RelativePath.Elements) == 0 {
				results[i] = ua.BrowsePathResult{StatusCode: ua.BadNothingToDo, Targets: []ua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			for _, element := range d.RelativePath.Elements {
				if element.TargetName.Name == "" {
					results[i] = ua.BrowsePathResult{StatusCode: ua.BadBrowseNameInvalid, Targets: []ua.BrowsePathTarget{}}
					wg.Done()
					return
				}
			}
			targets, err1 := srv.follow(d.StartingNode, d.RelativePath.Elements)
			if err1 == ua.BadNodeIDUnknown {
				results[i] = ua.BrowsePathResult{StatusCode: ua.BadNodeIDUnknown, Targets: []ua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if err1 == ua.BadNothingToDo {
				results[i] = ua.BrowsePathResult{StatusCode: ua.BadNothingToDo, Targets: []ua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if err1 == ua.BadNoMatch {
				results[i] = ua.BrowsePathResult{StatusCode: ua.BadNoMatch, Targets: []ua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if targets != nil {
				if len(targets) > 0 {
					results[i] = ua.BrowsePathResult{StatusCode: ua.Good, Targets: targets}
					wg.Done()
					return
				}
				results[i] = ua.BrowsePathResult{StatusCode: ua.BadNoMatch, Targets: targets}
				wg.Done()
				return
			}
			results[i] = ua.BrowsePathResult{StatusCode: ua.BadNoMatch, Targets: []ua.BrowsePathTarget{}}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.TranslateBrowsePathsToNodeIDsResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				Results: results,
			},
			requestid,
		)
	}()
	return nil
}

func (srv *Server) handleRegisterNodes(ch *serverSecureChannel, requestid uint32, req *ua.RegisterNodesRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.registerNodesCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.registerNodesErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.registerNodesErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.NodesToRegister)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.registerNodesErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerRegisterNodes) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.registerNodesErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]ua.NodeID, l)

	for ii := 0; ii < l; ii++ {
		results[ii] = req.NodesToRegister[ii]
	}

	ch.Write(
		&ua.RegisterNodesResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			RegisteredNodeIDs: results,
		},
		requestid,
	)
	return nil
}

func (srv *Server) handleUnregisterNodes(ch *serverSecureChannel, requestid uint32, req *ua.UnregisterNodesRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.unregisterNodesCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.unregisterNodesErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.unregisterNodesErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.NodesToUnregister)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.unregisterNodesErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerRegisterNodes) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.unregisterNodesErrorCount++
		session.errorCount++
		return nil
	}

	ch.Write(
		&ua.UnregisterNodesResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
		},
		requestid,
	)
	return nil
}

func (srv *Server) follow(nodeID ua.NodeID, elements []ua.RelativePathElement) ([]ua.BrowsePathTarget, error) {
	if len(elements) == 0 {
		return nil, ua.BadNothingToDo
	} else if len(elements) == 1 {
		ns, err2 := srv.target(nodeID, elements[0])
		if err2 != nil {
			return nil, err2
		}
		targets := make([]ua.BrowsePathTarget, len(ns))
		for i, n := range ns {
			targets[i] = ua.BrowsePathTarget{TargetID: n, RemainingPathIndex: math.MaxUint32}
		}
		return targets, nil
	} else {
		e := elements[0]
		ns2, err3 := srv.target(nodeID, e)
		if err3 != nil {
			return nil, err3
		}
		var nextID ua.ExpandedNodeID
		if len(ns2) > 0 {
			nextID = ns2[0]
		}
		nextElements := make([]ua.RelativePathElement, len(elements)-1)
		copy(nextElements, elements[1:])
		nextNode, ok := srv.NamespaceManager().FindNode(ua.ToNodeID(nextID, srv.NamespaceUris()))
		if ok {
			return srv.follow(nextNode.NodeID(), nextElements)
		}
		if len(nextElements) == 0 {
			return []ua.BrowsePathTarget{
				{TargetID: nextID, RemainingPathIndex: math.MaxUint32},
			}, nil
		}
		return []ua.BrowsePathTarget{
			{TargetID: nextID, RemainingPathIndex: uint32(len(nextElements))},
		}, nil
	}
}

// target returns a slice of target nodeid's that match the given RelativePathElement
func (srv *Server) target(nodeID ua.NodeID, element ua.RelativePathElement) ([]ua.ExpandedNodeID, error) {
	referenceTypeID := element.ReferenceTypeID
	includeSubtypes := element.IncludeSubtypes
	isInverse := element.IsInverse
	targetName := element.TargetName
	m := srv.NamespaceManager()
	node, ok := m.FindNode(nodeID)
	if !ok {
		return nil, ua.BadNodeIDUnknown
	}
	refs := node.References()
	targets := make([]ua.ExpandedNodeID, 0, 4)
	for _, r := range refs {
		if !(r.IsInverse == isInverse) {
			continue
		}
		if !(referenceTypeID == nil || r.ReferenceTypeID == referenceTypeID || (includeSubtypes && m.IsSubtype(r.ReferenceTypeID, referenceTypeID))) {
			continue
		}
		t, ok := m.FindNode(ua.ToNodeID(r.TargetID, srv.NamespaceUris()))
		if !ok {
			continue
		}
		if !(targetName == t.BrowseName()) {
			continue
		}
		targets = append(targets, r.TargetID)
	}
	if len(targets) == 0 {
		return nil, ua.BadNoMatch
	}
	return targets, nil
}

// Read returns a list of Node attributes.
func (srv *Server) handleRead(ch *serverSecureChannel, requestid uint32, req *ua.ReadRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.readCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// check MaxAge
	if req.MaxAge < 0.0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadMaxAgeInvalid,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	// check TimestampsToReturn
	if req.TimestampsToReturn < ua.TimestampsToReturnSource || req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTimestampsToReturnInvalid,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	// check nothing to do
	l := len(req.NodesToRead)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerRead) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.DataValue, l)
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			n := req.NodesToRead[i]
			results[i] = srv.readValue(ctx, n)
			wg.Done()
		})
	}
	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.ReadResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
				},
				Results: selectTimestamps(results, req.TimestampsToReturn),
			},
			requestid,
		)
	}()
	return nil
}

// Write sets a list of Node attributes.
func (srv *Server) handleWrite(ch *serverSecureChannel, requestid uint32, req *ua.WriteRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.writeCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.writeErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.writeErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// check nothing to do
	l := len(req.NodesToWrite)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.writeErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerWrite) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.writeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.StatusCode, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			n := req.NodesToWrite[i]
			results[i] = srv.writeValue(ctx, n)
			wg.Done()
		})
	}
	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.WriteResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now().UTC(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				Results: results,
			},
			requestid,
		)

	}()
	return nil
}

// HistoryRead returns a list of historical values.
func (srv *Server) handleHistoryRead(ch *serverSecureChannel, requestid uint32, req *ua.HistoryReadRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	// session.readCount++
	// session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		// session.readErrorCount++
		// session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		// session.readErrorCount++
		// session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// check TimestampsToReturn
	if req.TimestampsToReturn < ua.TimestampsToReturnSource || req.TimestampsToReturn > ua.TimestampsToReturnBoth {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadInvalidTimestampArgument,
				},
			},
			requestid,
		)
		// session.readErrorCount++
		// session.errorCount++
		return nil
	}
	// check nothing to do
	l := len(req.NodesToRead)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		// session.readErrorCount++
		// session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryReadData) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		// session.readErrorCount++
		// session.errorCount++
		return nil
	}

	// check if historian installed
	h := srv.Historian()
	if h == nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadHistoryOperationUnsupported,
				},
			},
			requestid,
		)
		return nil
	}

	switch details := req.HistoryReadDetails.(type) {
	case ua.ReadEventDetails:
		results, status := h.ReadEvent(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&ua.HistoryReadResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case ua.ReadRawModifiedDetails:
		results, status := h.ReadRawModified(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&ua.HistoryReadResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case ua.ReadProcessedDetails:
		results, status := h.ReadProcessed(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&ua.HistoryReadResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case ua.ReadAtTimeDetails:
		results, status := h.ReadAtTime(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&ua.HistoryReadResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil
	}

	ch.Write(
		&ua.ServiceFault{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHandle,
				ServiceResult: ua.BadHistoryOperationInvalid,
			},
		},
		requestid,
	)
	return nil
}

// readRange returns slice of value specified by IndexRange
func readRange(source ua.DataValue, indexRange string) ua.DataValue {
	if indexRange == "" {
		return source
	}
	ranges := strings.Split(indexRange, ",")
	switch src := source.Value.(type) {
	case string:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		v1 := []rune(src)
		i, j, status := parseBounds(ranges[0], len(v1))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]rune, j-i)
		copy(dst, v1[i:j])
		return ua.NewDataValue(string(dst), source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case ua.ByteString:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		v1 := []byte(src)
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]byte, j-i)
		copy(dst, v1[i:j])
		return ua.NewDataValue(ua.ByteString(dst), source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []bool:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]bool, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int8:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int8, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []byte:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]byte, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int16:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int16, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint16:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint16, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int32:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int32, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint32:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint32, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int64:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int64, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint64:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint64, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []float32:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]float32, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []float64:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]float64, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []string:
		if len(ranges) > 2 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]string, j-i)
		copy(dst, src[i:j])
		if len(ranges) > 1 {
			for ii := range dst {
				v1 := []rune(dst[ii])
				i, j, status := parseBounds(ranges[1], len(v1))
				if status.IsBad() {
					return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
				}
				dst2 := make([]rune, j-i)
				copy(dst2, v1[i:j])
				dst[ii] = string(dst2)
			}
		}
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []time.Time:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]time.Time, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uuid.UUID:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uuid.UUID, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.ByteString:
		if len(ranges) > 2 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.ByteString, j-i)
		copy(dst, src[i:j])
		if len(ranges) > 1 {
			for ii := range dst {
				i, j, status := parseBounds(ranges[1], len(dst[ii]))
				if status.IsBad() {
					return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
				}
				dst2 := make([]byte, j-i)
				copy(dst2, dst[ii][i:j])
				dst[ii] = ua.ByteString(dst2)
			}
		}
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.XMLElement:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.XMLElement, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.NodeID:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.NodeID, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.ExpandedNodeID:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.ExpandedNodeID, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.StatusCode:
		i, j, status := parseBounds(ranges[0], len(src))
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.StatusCode, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.QualifiedName:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.QualifiedName, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.LocalizedText:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.LocalizedText, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.ExtensionObject:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.ExtensionObject, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.DataValue:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.DataValue, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.Variant:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.Variant, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []ua.DiagnosticInfo:
		if len(ranges) > 1 {
			return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]ua.DiagnosticInfo, j-i)
		copy(dst, src[i:j])
		return ua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	default:
		return ua.NewDataValue(nil, ua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	}
}

// writeRange sets subset of value specified by IndexRange
func writeRange(source ua.DataValue, value ua.DataValue, indexRange string) (ua.DataValue, ua.StatusCode) {
	if indexRange == "" {
		return ua.NewDataValue(value.Value, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	}
	ranges := strings.Split(indexRange, ",")
	switch src := source.Value.(type) {
	case string:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		v1 := []rune(src)
		i, j, status := parseBounds(ranges[0], len(v1))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := []rune(value.Value.(string))
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]rune, len(v1))
		copy(dst, v1)
		copy(dst[i:j], v2)
		return ua.NewDataValue(string(dst), value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case ua.ByteString:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.(ua.ByteString)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]byte, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(ua.ByteString(dst), value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []bool:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]bool)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]bool, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []int8:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]int8)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]int8, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []byte:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]byte)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]byte, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []int16:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]int16)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]int16, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []uint16:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]uint16)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]uint16, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []int32:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]int32)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]int32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []uint32:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]uint32)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]uint32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []int64:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]int64)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]int64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []uint64:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]uint64)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]uint64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []float32:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]float32)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]float32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []float64:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]float64)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]float64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []string:
		if len(ranges) > 2 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]string)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]string, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []time.Time:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]time.Time)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]time.Time, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []uuid.UUID:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]uuid.UUID)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]uuid.UUID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.ByteString:
		if len(ranges) > 2 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.ByteString)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.ByteString, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.XMLElement:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.XMLElement)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.XMLElement, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.NodeID:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.NodeID)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.NodeID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.ExpandedNodeID:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.ExpandedNodeID)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.ExpandedNodeID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.StatusCode:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.StatusCode)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.StatusCode, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.QualifiedName:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.QualifiedName)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.QualifiedName, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.LocalizedText:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.LocalizedText)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.LocalizedText, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.ExtensionObject:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.ExtensionObject)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.ExtensionObject, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.DataValue:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.DataValue)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.DataValue, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.Variant:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.Variant)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.Variant, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	case []ua.DiagnosticInfo:
		if len(ranges) > 1 {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return ua.NilDataValue, status
		}
		v2 := value.Value.([]ua.DiagnosticInfo)
		if j-i != len(v2) {
			return ua.NilDataValue, ua.BadIndexRangeNoData
		}
		dst := make([]ua.DiagnosticInfo, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return ua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), ua.Good
	default:
		return ua.NilDataValue, ua.BadIndexRangeNoData
	}
}

func parseBounds(s string, length int) (int, int, ua.StatusCode) {
	lo := int64(-1)
	hi := int64(-1)
	len := int64(length)
	var err error

	if len == 0 {
		return -1, -1, ua.BadIndexRangeNoData
	}

	if s == "" {
		return 0, length, ua.Good
	}

	index := strings.Index(s, ":")
	if index != -1 {
		lo, err = strconv.ParseInt(s[:index], 10, 32)
		if err != nil {
			return -1, -1, ua.BadIndexRangeInvalid
		}
		hi, err = strconv.ParseInt(s[index+1:], 10, 32)
		if err != nil {
			return -1, -1, ua.BadIndexRangeInvalid
		}
		if hi < 0 {
			return -1, -1, ua.BadIndexRangeInvalid
		}
		if lo >= hi {
			return -1, -1, ua.BadIndexRangeInvalid
		}
	} else {
		lo, err = strconv.ParseInt(s, 10, 32)
		if err != nil {
			return -1, -1, ua.BadIndexRangeInvalid
		}
	}
	if lo < 0 {
		return -1, -1, ua.BadIndexRangeInvalid
	}
	// now check if no data in range
	if lo >= len {
		return -1, -1, ua.BadIndexRangeNoData
	}
	// limit hi
	if hi >= len {
		hi = len - 1
	}
	// adapt to slice style
	if hi == -1 {
		hi = lo
	}
	hi++

	return int(lo), int(hi), ua.Good
}

// selectTimestamps returns new instances of DataValue with only the selected timestamps.
func selectTimestamps(values []ua.DataValue, timestampsToReturn ua.TimestampsToReturn) []ua.DataValue {
	switch timestampsToReturn {
	case ua.TimestampsToReturnSource:
		for i, value := range values {
			values[i] = ua.NewDataValue(value.Value, value.StatusCode, value.SourceTimestamp, 0, time.Time{}, 0)
		}
		return values
	case ua.TimestampsToReturnServer:
		for i, value := range values {
			values[i] = ua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, value.ServerTimestamp, 0)
		}
		return values
	case ua.TimestampsToReturnNeither:
		for i, value := range values {
			values[i] = ua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, time.Time{}, 0)
		}
		return values
	default:
		return values
	}
}

// Call invokes a list of Methods.
func (srv *Server) handleCall(ch *serverSecureChannel, requestid uint32, req *ua.CallRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.callCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.callErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.callErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	l := len(req.MethodsToCall)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.callErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxNodesPerMethodCall) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.callErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.CallMethodResult, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			n := req.MethodsToCall[i]
			m := srv.NamespaceManager()
			n1, ok := m.FindNode(n.ObjectID)
			if !ok {
				results[i] = ua.CallMethodResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp := n1.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
				results[i] = ua.CallMethodResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			switch n1.(type) {
			case *ObjectNode:
			case *ObjectTypeNode:
			default:
				results[i] = ua.CallMethodResult{StatusCode: ua.BadNodeClassInvalid}
				wg.Done()
				return
			}
			n2, ok := m.FindNode(n.MethodID)
			if !ok {
				results[i] = ua.CallMethodResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp = n2.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
				results[i] = ua.CallMethodResult{StatusCode: ua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			// TODO: check if method is hasComponent of object or objectType
			switch n3 := n2.(type) {
			case *MethodNode:
				if !n3.UserExecutable(ctx) {
					results[i] = ua.CallMethodResult{StatusCode: ua.BadUserAccessDenied}
				} else {
					if n3.callMethodHandler != nil {
						results[i] = n3.callMethodHandler(ctx, n)
					} else {
						results[i] = ua.CallMethodResult{StatusCode: ua.BadNotImplemented}
					}
				}
			default:
				results[i] = ua.CallMethodResult{StatusCode: ua.BadAttributeIDInvalid}
			}
			wg.Done()
		})
	}
	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&ua.CallResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				Results: results,
			},
			requestid,
		)
	}()
	return nil
}

// CreateMonitoredItems creates and adds one or more MonitoredItems to a Subscription.
func (srv *Server) handleCreateMonitoredItems(ch *serverSecureChannel, requestid uint32, req *ua.CreateMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.createMonitoredItemsCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	sub.Lock()
	sub.lifetimeCounter = 0
	sub.Unlock()

	if req.TimestampsToReturn < ua.TimestampsToReturnSource || req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTimestampsToReturnInvalid,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.ItemsToCreate)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.MonitoredItemCreateResult, l)
	minSupportedSampleRate := srv.ServerCapabilities().MinSupportedSampleRate
	for i, item := range req.ItemsToCreate {
		n, ok := srv.NamespaceManager().FindNode(item.ItemToMonitor.NodeID)
		if !ok {
			results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadNodeIDUnknown}
			continue
		}
		attr := item.ItemToMonitor.AttributeID
		if !n.IsAttributeIDValid(attr) {
			results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadAttributeIDInvalid}
			continue
		}
		switch attr {
		case ua.AttributeIDValue:
			n2, ok := n.(*VariableNode)
			if !ok {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadAttributeIDInvalid}
				continue
			}
			// check AccessLevel
			if (n2.AccessLevel() & ua.AccessLevelsCurrentRead) == 0 {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadNotReadable}
				continue
			}
			if (n2.UserAccessLevel(ctx) & ua.AccessLevelsCurrentRead) == 0 {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadUserAccessDenied}
				continue
			}
			if sc := srv.validateIndexRange(ctx, item.ItemToMonitor.IndexRange, n2.DataType(), n2.ValueRank()); sc != ua.Good {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: sc}
				continue
			}
			if item.RequestedParameters.Filter == nil {
				item.RequestedParameters.Filter = ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}
			}
			dcf, ok := item.RequestedParameters.Filter.(ua.DataChangeFilter)
			if !ok {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadFilterNotAllowed}
				continue
			}
			if dcf.DeadbandType != uint32(ua.DeadbandTypeNone) {
				destType := srv.NamespaceManager().FindVariantType(n2.DataType())
				switch destType {
				case ua.VariantTypeByte, ua.VariantTypeSByte:
				case ua.VariantTypeInt16, ua.VariantTypeInt32, ua.VariantTypeInt64:
				case ua.VariantTypeUInt16, ua.VariantTypeUInt32, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat, ua.VariantTypeDouble:
				default:
					results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadFilterNotAllowed}
					continue
				}
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, minSupportedSampleRate)
			sub.AppendItem(mi)
			results[i] = ua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		case ua.AttributeIDEventNotifier:
			n2, ok := n.(*ObjectNode)
			if !ok {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadAttributeIDInvalid}
				continue
			}
			// check EventNotifier
			if (n2.EventNotifier() & ua.EventNotifierSubscribeToEvents) == 0 {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadNotReadable}
				continue
			}
			rp := n2.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, ua.PermissionTypeReceiveEvents) {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadUserAccessDenied}
				continue
			}
			if item.RequestedParameters.Filter == nil {
				item.RequestedParameters.Filter = ua.EventFilter{} // TODO: get EventBase select clause
			}
			_, ok = item.RequestedParameters.Filter.(ua.EventFilter)
			if !ok {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadFilterNotAllowed}
				continue
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, 0.0)
			sub.AppendItem(mi)
			results[i] = ua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		default:
			rp := n.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadAttributeIDInvalid}
				continue
			}
			if item.RequestedParameters.Filter != nil {
				results[i] = ua.MonitoredItemCreateResult{StatusCode: ua.BadFilterNotAllowed}
				continue
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, minSupportedSampleRate)
			sub.AppendItem(mi)
			results[i] = ua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		}
	}

	ch.Write(
		&ua.CreateMonitoredItemsResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

// ModifyMonitoredItems modifies MonitoredItems of a Subscription.
func (srv *Server) handleModifyMonitoredItems(ch *serverSecureChannel, requestid uint32, req *ua.ModifyMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.modifyMonitoredItemsCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	sub.Lock()
	sub.lifetimeCounter = 0
	sub.Unlock()

	if req.TimestampsToReturn < ua.TimestampsToReturnSource || req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTimestampsToReturnInvalid,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	l := len(req.ItemsToModify)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.MonitoredItemModifyResult, l)

	for i, modifyReq := range req.ItemsToModify {
		if item, ok := sub.FindItem(modifyReq.MonitoredItemID); ok {
			attr := item.itemToMonitor.AttributeID
			switch {
			case attr == ua.AttributeIDValue:
				if modifyReq.RequestedParameters.Filter == nil {
					modifyReq.RequestedParameters.Filter = ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}
				}
				dcf, ok := modifyReq.RequestedParameters.Filter.(ua.DataChangeFilter)
				if !ok {
					results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.BadFilterNotAllowed}
					continue
				}
				if dcf.DeadbandType != uint32(ua.DeadbandTypeNone) {
					destType := srv.NamespaceManager().FindVariantType(item.node.(*VariableNode).DataType())
					switch destType {
					case ua.VariantTypeByte, ua.VariantTypeSByte:
					case ua.VariantTypeInt16, ua.VariantTypeInt32, ua.VariantTypeInt64:
					case ua.VariantTypeUInt16, ua.VariantTypeUInt32, ua.VariantTypeUInt64:
					case ua.VariantTypeFloat, ua.VariantTypeDouble:
					default:
						results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.BadFilterNotAllowed}
						continue
					}
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			case attr == ua.AttributeIDEventNotifier:
				if modifyReq.RequestedParameters.Filter == nil {
					modifyReq.RequestedParameters.Filter = ua.EventFilter{} // TODO: get EventBase select clause
				}
				_, ok := modifyReq.RequestedParameters.Filter.(ua.EventFilter)
				if !ok {
					results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.BadFilterNotAllowed}
					continue
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			default:
				if modifyReq.RequestedParameters.Filter != nil {
					results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.BadFilterNotAllowed}
					continue
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			}
		} else {
			results[i] = ua.MonitoredItemModifyResult{StatusCode: ua.BadMonitoredItemIDInvalid}
		}
	}

	ch.Write(
		&ua.ModifyMonitoredItemsResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

// SetMonitoringMode sets the monitoring mode for one or more MonitoredItems of a Subscription.
func (srv *Server) handleSetMonitoringMode(ch *serverSecureChannel, requestid uint32, req *ua.SetMonitoringModeRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.setMonitoringModeCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}
	sub.Lock()
	sub.lifetimeCounter = 0
	sub.Unlock()

	l := len(req.MonitoredItemIDs)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.StatusCode, l)

	for i, id := range req.MonitoredItemIDs {
		if item, ok := sub.FindItem(id); ok {
			item.SetMonitoringMode(ctx, req.MonitoringMode)
			results[i] = ua.Good
		} else {
			results[i] = ua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&ua.SetMonitoringModeResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

// SetTriggering creates and deletes triggering links for a triggering item.
func (srv *Server) handleSetTriggering(ch *serverSecureChannel, requestid uint32, req *ua.SetTriggeringRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.setTriggeringCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}
	sub.Lock()
	sub.lifetimeCounter = 0
	sub.Unlock()

	if len(req.LinksToRemove) == 0 && len(req.LinksToAdd) == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}

	trigger, ok := sub.FindItem(req.TriggeringItemID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadMonitoredItemIDInvalid,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}

	removeResults := make([]ua.StatusCode, len(req.LinksToRemove))
	for i, link := range req.LinksToRemove {
		triggered, ok := sub.FindItem(link)
		if !ok {
			removeResults[i] = ua.BadMonitoredItemIDInvalid
			continue
		}
		if trigger.RemoveTriggeredItem(triggered) {
			removeResults[i] = ua.Good
		} else {
			removeResults[i] = ua.BadMonitoredItemIDInvalid
		}
	}

	addResults := make([]ua.StatusCode, len(req.LinksToAdd))
	for i, link := range req.LinksToAdd {
		triggered, ok := sub.FindItem(link)
		if !ok {
			addResults[i] = ua.BadMonitoredItemIDInvalid
			continue
		}
		if trigger.AddTriggeredItem(triggered) {
			addResults[i] = ua.Good
		} else {
			addResults[i] = ua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&ua.SetTriggeringResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			AddResults:    addResults,
			RemoveResults: removeResults,
		},
		requestid,
	)
	return nil
}

// DeleteMonitoredItems removes one or more MonitoredItems of a Subscription.
func (srv *Server) handleDeleteMonitoredItems(ch *serverSecureChannel, requestid uint32, req *ua.DeleteMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.deleteMonitoredItemsCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, SessionKey, session)

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	sub.Lock()
	sub.lifetimeCounter = 0
	sub.Unlock()

	l := len(req.MonitoredItemIDs)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	// check too many operations
	if l > int(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall) {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]ua.StatusCode, l)

	for i, id := range req.MonitoredItemIDs {
		if ok := sub.DeleteItem(ctx, id); ok {
			results[i] = ua.Good
		} else {
			results[i] = ua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&ua.DeleteMonitoredItemsResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

func (srv *Server) validateIndexRange(ctx context.Context, s string, dataType ua.NodeID, rank int32) ua.StatusCode {
	lo := int64(-1)
	hi := int64(-1)
	var err error

	if s == "" {
		return ua.Good
	}

	ranges := strings.Split(s, ",")
	for _, r := range ranges {
		index := strings.Index(r, ":")
		if index != -1 {
			lo, err = strconv.ParseInt(r[:index], 10, 32)
			if err != nil {
				return ua.BadIndexRangeInvalid
			}
			hi, err = strconv.ParseInt(r[index+1:], 10, 32)
			if err != nil {
				return ua.BadIndexRangeInvalid
			}
			if hi < 0 {
				return ua.BadIndexRangeInvalid
			}
			if lo >= hi {
				return ua.BadIndexRangeInvalid
			}
		} else {
			lo, err = strconv.ParseInt(r, 10, 32)
			if err != nil {
				return ua.BadIndexRangeInvalid
			}
		}
		if lo < 0 {
			return ua.BadIndexRangeInvalid
		}
	}

	destType := srv.NamespaceManager().FindVariantType(dataType)

	switch rank {
	case ua.ValueRankScalarOrOneDimension:
		diff := len(ranges) - 1
		if !(diff == 0) {
			if !(diff == 1 && (destType == ua.VariantTypeString || destType == ua.VariantTypeByteString)) {
				return ua.BadIndexRangeNoData
			}
		}
	case ua.ValueRankAny:
	case ua.ValueRankScalar:
		if !(len(ranges) == 1 && (destType == ua.VariantTypeString || destType == ua.VariantTypeByteString)) {
			return ua.BadIndexRangeNoData
		}
	case ua.ValueRankOneOrMoreDimensions:
	default:
		diff := len(ranges) - int(rank)
		if !(diff == 0) {
			if !(diff == 1 && (destType == ua.VariantTypeString || destType == ua.VariantTypeByteString)) {
				return ua.BadIndexRangeNoData
			}
		}
	}

	return ua.Good
}

// CreateSubscription creates a Subscription.
func (srv *Server) handleCreateSubscription(ch *serverSecureChannel, requestid uint32, req *ua.CreateSubscriptionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.createSubscriptionCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.createSubscriptionErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.createSubscriptionErrorCount++
		session.errorCount++
		return nil
	}

	sm := srv.SubscriptionManager()
	s := NewSubscription(sm, session, req.RequestedPublishingInterval, req.RequestedLifetimeCount, req.RequestedMaxKeepAliveCount, req.MaxNotificationsPerPublish, req.PublishingEnabled, req.Priority)
	if err := sm.Add(s); err != nil {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadTooManySubscriptions,
				},
			},
			requestid,
		)
		session.createSubscriptionErrorCount++
		session.errorCount++
		return nil
	}
	s.startPublishing()
	// log.Printf("Created subscription '%d'.\n", s.id)

	ch.Write(
		&ua.CreateSubscriptionResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			SubscriptionID:            s.id,
			RevisedPublishingInterval: s.publishingInterval,
			RevisedLifetimeCount:      s.lifetimeCount,
			RevisedMaxKeepAliveCount:  s.maxKeepAliveCount,
		},
		requestid,
	)
	return nil
}

// ModifySubscription modifies a Subscription.
func (srv *Server) handleModifySubscription(ch *serverSecureChannel, requestid uint32, req *ua.ModifySubscriptionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.modifySubscriptionCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.modifySubscriptionErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.modifySubscriptionErrorCount++
		session.errorCount++
		return nil
	}

	// get subscription
	sub, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.modifySubscriptionErrorCount++
		session.errorCount++
		return nil
	}

	sub.Modify(req.RequestedPublishingInterval, req.RequestedLifetimeCount, req.RequestedMaxKeepAliveCount, req.MaxNotificationsPerPublish, req.Priority)

	ch.Write(
		&ua.ModifySubscriptionResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			RevisedPublishingInterval: sub.publishingInterval,
			RevisedLifetimeCount:      sub.lifetimeCount,
			RevisedMaxKeepAliveCount:  sub.maxKeepAliveCount,
		},
		requestid,
	)
	return nil
}

// SetPublishingMode enables sending of Notifications on one or more Subscriptions.
func (srv *Server) handleSetPublishingMode(ch *serverSecureChannel, requestid uint32, req *ua.SetPublishingModeRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.setPublishingModeCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.setPublishingModeErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.setPublishingModeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	sm := srv.SubscriptionManager()
	for i, id := range req.SubscriptionIDs {
		s, ok := sm.Get(id)
		if ok {
			s.SetPublishingMode(req.PublishingEnabled)
			results[i] = ua.Good
		} else {
			results[i] = ua.BadSubscriptionIDInvalid
		}
	}
	ch.Write(
		&ua.SetPublishingModeResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

// TransferSubscriptions transfers a Subscription and its MonitoredItems from one Session to another.

// DeleteSubscriptions deletes one or more Subscriptions.
func (srv *Server) handleDeleteSubscriptions(ch *serverSecureChannel, requestid uint32, req *ua.DeleteSubscriptionsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.deleteSubscriptionsCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.deleteSubscriptionsErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	l := len(req.SubscriptionIDs)
	if l == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.deleteSubscriptionsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]ua.StatusCode, l)
	sm := srv.SubscriptionManager()
	for i, id := range req.SubscriptionIDs {
		if s, ok := sm.Get(id); ok {
			sm.Delete(s)
			s.Delete()
			// log.Printf("Deleted subscription '%d'.\n", id)
			results[i] = ua.Good
		} else {
			results[i] = ua.BadSubscriptionIDInvalid
		}
	}
	ch.Write(
		&ua.DeleteSubscriptionsResponse{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	// if no more subscriptions, then drain publishRequests
	if len(sm.GetBySession(session)) == 0 {
		ch, requestid, req, _, ok := session.removePublishRequest()
		for ok {
			ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: ua.BadNoSubscription,
					},
				},
				requestid,
			)
			session.publishErrorCount++
			session.errorCount++
			ch, requestid, req, _, ok = session.removePublishRequest()
		}
	}
	return nil
}

// Publish returns a NotificationMessage or a keep-alive Message.
func (srv *Server) handlePublish(ch *serverSecureChannel, requestid uint32, req *ua.PublishRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.publishCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.publishErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.publishErrorCount++
		session.errorCount++
		return nil
	}

	sm := srv.SubscriptionManager()

	// process sub ack's
	results := make([]ua.StatusCode, len(req.SubscriptionAcknowledgements))
	for i, sa := range req.SubscriptionAcknowledgements {
		if sub, ok := sm.Get(sa.SubscriptionID); ok {
			if sub.acknowledge(sa.SequenceNumber) {
				results[i] = ua.Good
			} else {
				results[i] = ua.BadSequenceNumberUnknown
			}
		} else {
			results[i] = ua.BadSubscriptionIDInvalid
		}
	}

	// process status changes
	select {
	case op := <-session.stateChanges:
		// q := s.retransmissionQueue
		// for e := q.Front(); e != nil && q.Len() >= maxRetransmissionQueueLength; e = e.Next() {
		// 	q.Remove(e)
		// }
		// nm := op.message
		// q.PushBack(nm)
		// avail := make([]uint32, 0, 4)
		// for e := q.Front(); e != nil; e = e.Next() {
		// 	if nm, ok := e.Value.(*NotificationMessage); ok {
		// 		avail = append(avail, nm.SequenceNumber)
		// 	}
		// }
		ch.Write(
			&ua.PublishResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				SubscriptionID:           op.subscriptionId,
				AvailableSequenceNumbers: []uint32{},
				MoreNotifications:        false,
				NotificationMessage:      op.message,
				Results:                  results,
				DiagnosticInfos:          nil,
			},
			requestid,
		)
		return nil
	default:
	}

	if sm.Len() == 0 {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadNoSubscription,
				},
			},
			requestid,
		)
		session.publishErrorCount++
		session.errorCount++
		return nil
	}

	subs := sm.GetBySession(session)
	sort.Slice(subs, func(i, j int) bool {
		return subs[i].priority > subs[j].priority
	})

	for _, sub := range subs {
		if sub.handleLatePublishRequest(ch, requestid, req, results) {
			return nil
		}
	}

	session.addPublishRequest(ch, requestid, req, results)
	return nil
}

// Republish requests the Server to republish a NotificationMessage from its retransmission queue.
func (srv *Server) handleRepublish(ch *serverSecureChannel, requestid uint32, req *ua.RepublishRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(ua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}
	session.republishCount++
	session.requestCount++
	// check channelId
	id := session.SecureChannelId()
	if id == 0 {
		srv.SessionManager().Delete(session)
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		session.republishErrorCount++
		session.errorCount++
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.republishErrorCount++
		session.errorCount++
		return nil
	}

	s, ok := srv.SubscriptionManager().Get(req.SubscriptionID)
	if !ok {
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: ua.BadSubscriptionIDInvalid,
				},
			},
			requestid,
		)
		session.republishErrorCount++
		session.errorCount++
		return nil
	}

	s.Lock()
	s.lifetimeCounter = 0
	s.Unlock()

	s.republishRequestCount++
	s.republishMessageRequestCount++
	q := s.retransmissionQueue
	for e := q.Front(); e != nil; e = e.Next() {
		if nm, ok := e.Value.(ua.NotificationMessage); ok {
			if req.RetransmitSequenceNumber == nm.SequenceNumber {
				ch.Write(
					&ua.RepublishResponse{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHeader.RequestHandle,
						},
						NotificationMessage: nm,
					},
					requestid,
				)
				s.republishMessageCount++
				q.Remove(e)
				e.Value = nil
				return nil
			}
		}
	}
	ch.Write(
		&ua.ServiceFault{
			ResponseHeader: ua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHandle,
				ServiceResult: ua.BadMessageNotAvailable,
			},
		},
		requestid,
	)
	session.republishErrorCount++
	session.errorCount++
	return nil
}

// WriteValue writes the value of the attribute.
func (srv *Server) writeValue(ctx context.Context, writeValue ua.WriteValue) ua.StatusCode {
	n, ok := srv.NamespaceManager().FindNode(writeValue.NodeID)
	if !ok {
		return ua.BadNodeIDUnknown
	}
	rp := n.UserRolePermissions(ctx)
	if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
		return ua.BadNodeIDUnknown
	}
	switch writeValue.AttributeID {
	case ua.AttributeIDValue:
		switch n1 := n.(type) {
		case *VariableNode:
			// if writeValue.Value.StatusCode != Good || !time.Time.IsZero(writeValue.Value.ServerTimestamp) || !time.Time.IsZero(writeValue.Value.SourceTimestamp) {
			// 	return ua.BadWriteNotSupported
			// }
			if (n1.AccessLevel() & ua.AccessLevelsCurrentWrite) == 0 {
				return ua.BadNotWritable
			}
			if (n1.UserAccessLevel(ctx) & ua.AccessLevelsCurrentWrite) == 0 {
				return ua.BadUserAccessDenied
			}
			// check data type
			destType := srv.NamespaceManager().FindVariantType(n1.DataType())
			destRank := n1.ValueRank()
			// special case convert bytestring to byte array
			if destType == ua.VariantTypeByte && destRank == ua.ValueRankOneDimension {
				if v1, ok := writeValue.Value.Value.(ua.ByteString); ok {
					writeValue.Value.Value = []byte(v1)
				}
			}
			// special case convert byte array to bytestring
			if destType == ua.VariantTypeByteString && destRank == ua.ValueRankScalar {
				if v1, ok := writeValue.Value.Value.([]byte); ok {
					writeValue.Value.Value = ua.ByteString(v1)
				}
			}
			switch v2 := writeValue.Value.Value.(type) {
			case nil:
			case bool:
				if destType != ua.VariantTypeBoolean && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case int8:
				if destType != ua.VariantTypeSByte && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case uint8:
				if destType != ua.VariantTypeByte && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case int16:
				if destType != ua.VariantTypeInt16 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case uint16:
				if destType != ua.VariantTypeUInt16 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case int32:
				if destType != ua.VariantTypeInt32 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case uint32:
				if destType != ua.VariantTypeUInt32 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case int64:
				if destType != ua.VariantTypeInt64 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case uint64:
				if destType != ua.VariantTypeUInt64 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case float32:
				if destType != ua.VariantTypeFloat && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case float64:
				if destType != ua.VariantTypeDouble && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case string:
				if len(v2) > int(srv.serverCapabilities.MaxStringLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeString && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case time.Time:
				if destType != ua.VariantTypeDateTime && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case uuid.UUID:
				if destType != ua.VariantTypeGUID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.ByteString:
				if len(v2) > int(srv.serverCapabilities.MaxByteStringLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeByteString && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.XMLElement:
				if destType != ua.VariantTypeXMLElement && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.NodeID:
				if destType != ua.VariantTypeNodeID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.ExpandedNodeID:
				if destType != ua.VariantTypeExpandedNodeID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.StatusCode:
				if destType != ua.VariantTypeStatusCode && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.QualifiedName:
				if destType != ua.VariantTypeQualifiedName && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case ua.LocalizedText:
				if destType != ua.VariantTypeLocalizedText && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []bool:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeBoolean && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []int8:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeSByte && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []uint8:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeByte && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []int16:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeInt16 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []uint16:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeUInt16 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []int32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeInt32 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []uint32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeUInt32 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []int64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeInt64 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []uint64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeUInt64 && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []float32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeFloat && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []float64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeDouble && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []string:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeString && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []time.Time:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeDateTime && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []uuid.UUID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeGUID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.ByteString:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeByteString && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.XMLElement:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeXMLElement && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.NodeID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeNodeID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.ExpandedNodeID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeExpandedNodeID && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.StatusCode:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeStatusCode && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.QualifiedName:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeQualifiedName && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.LocalizedText:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeLocalizedText && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.ExtensionObject:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeExtensionObject && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.DataValue:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeDataValue && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			case []ua.Variant:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return ua.BadOutOfRange
				}
				if destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankOneDimension && destRank != ua.ValueRankOneOrMoreDimensions && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			default:
				// case ua.ExtensionObject:
				if destType != ua.VariantTypeExtensionObject && destType != ua.VariantTypeVariant {
					return ua.BadTypeMismatch
				}
				if destRank != ua.ValueRankScalar && destRank != ua.ValueRankScalarOrOneDimension && destRank != ua.ValueRankAny {
					return ua.BadTypeMismatch
				}
			}

			if f := n1.writeValueHandler; f != nil {
				return f(ctx, writeValue)
			} else {
				result, status := writeRange(n1.Value(), writeValue.Value, writeValue.IndexRange)
				if status == ua.Good {
					n1.SetValue(result)
				}
				return status
			}
		default:
			return ua.BadAttributeIDInvalid
		}
	case ua.AttributeIDHistorizing:
		switch n1 := n.(type) {
		case *VariableNode:
			// check for PermissionTypeWriteHistorizing
			if !IsUserPermitted(rp, ua.PermissionTypeWriteHistorizing) {
				return ua.BadUserAccessDenied
			}
			v, ok := writeValue.Value.Value.(bool)
			if !ok {
				return ua.BadTypeMismatch
			}
			n1.SetHistorizing(v)
			return ua.Good
		default:
			return ua.BadAttributeIDInvalid
		}
	default:
		return ua.BadAttributeIDInvalid
	}
}

// readValue returns the value of the attribute.
func (srv *Server) readValue(ctx context.Context, readValueId ua.ReadValueID) ua.DataValue {
	if readValueId.DataEncoding.Name != "" {
		return ua.NewDataValue(nil, ua.BadDataEncodingInvalid, time.Time{}, 0, time.Now(), 0)
	}
	if readValueId.IndexRange != "" && readValueId.AttributeID != ua.AttributeIDValue {
		return ua.NewDataValue(nil, ua.BadIndexRangeNoData, time.Time{}, 0, time.Now(), 0)
	}
	n, ok := srv.NamespaceManager().FindNode(readValueId.NodeID)
	if !ok {
		return ua.NewDataValue(nil, ua.BadNodeIDUnknown, time.Time{}, 0, time.Now(), 0)
	}
	rp := n.UserRolePermissions(ctx)
	if !IsUserPermitted(rp, ua.PermissionTypeBrowse) {
		return ua.NewDataValue(nil, ua.BadNodeIDUnknown, time.Time{}, 0, time.Now(), 0)
	}
	switch readValueId.AttributeID {
	case ua.AttributeIDValue:
		switch n1 := n.(type) {
		case *VariableNode:
			// check the access level for the variable.
			if (n1.AccessLevel() & ua.AccessLevelsCurrentRead) == 0 {
				return ua.NewDataValue(nil, ua.BadNotReadable, time.Time{}, 0, time.Now(), 0)
			}
			if (n1.UserAccessLevel(ctx) & ua.AccessLevelsCurrentRead) == 0 {
				return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Time{}, 0, time.Now(), 0)
			}
			if f := n1.readValueHandler; f != nil {
				return f(ctx, readValueId)
			}
			return readRange(n1.Value(), readValueId.IndexRange)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDNodeID:
		return ua.NewDataValue(n.NodeID(), ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDNodeClass:
		return ua.NewDataValue(int32(n.NodeClass()), ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDBrowseName:
		return ua.NewDataValue(n.BrowseName(), ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDDisplayName:
		return ua.NewDataValue(n.DisplayName(), ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDDescription:
		return ua.NewDataValue(n.Description(), ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDIsAbstract:
		switch n1 := n.(type) {
		case *DataTypeNode:
			return ua.NewDataValue(n1.IsAbstract(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *ObjectTypeNode:
			return ua.NewDataValue(n1.IsAbstract(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *ReferenceTypeNode:
			return ua.NewDataValue(n1.IsAbstract(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return ua.NewDataValue(n1.IsAbstract(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDSymmetric:
		switch n1 := n.(type) {
		case *ReferenceTypeNode:
			return ua.NewDataValue(n1.Symmetric(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDInverseName:
		switch n1 := n.(type) {
		case *ReferenceTypeNode:
			return ua.NewDataValue(n1.InverseName(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDContainsNoLoops:
		switch n1 := n.(type) {
		case *ViewNode:
			return ua.NewDataValue(n1.ContainsNoLoops(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDEventNotifier:
		switch n1 := n.(type) {
		case *ObjectNode:
			return ua.NewDataValue(n1.EventNotifier(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *ViewNode:
			return ua.NewDataValue(n1.EventNotifier(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDDataType:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.DataType(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return ua.NewDataValue(n1.DataType(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDValueRank:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.ValueRank(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return ua.NewDataValue(n1.ValueRank(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDArrayDimensions:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.ArrayDimensions(), ua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return ua.NewDataValue(n1.ArrayDimensions(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDAccessLevel:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.AccessLevel(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDUserAccessLevel:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.UserAccessLevel(ctx), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDMinimumSamplingInterval:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.MinimumSamplingInterval(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDHistorizing:
		switch n1 := n.(type) {
		case *VariableNode:
			return ua.NewDataValue(n1.Historizing(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDExecutable:
		switch n1 := n.(type) {
		case *MethodNode:
			return ua.NewDataValue(n1.Executable(), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDUserExecutable:
		switch n1 := n.(type) {
		case *MethodNode:
			return ua.NewDataValue(n1.UserExecutable(ctx), ua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDDataTypeDefinition:
		switch n1 := n.(type) {
		case *DataTypeNode:
			if def := n1.DataTypeDefinition(); def != nil {
				return ua.NewDataValue(def, ua.Good, time.Time{}, 0, time.Now(), 0)
			}
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		default:
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case ua.AttributeIDRolePermissions:
		if !IsUserPermitted(rp, ua.PermissionTypeReadRolePermissions) {
			return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
		s1 := n.RolePermissions()
		s2 := make([]ua.ExtensionObject, len(s1))
		for i := range s1 {
			s2[i] = s1[i]
		}
		return ua.NewDataValue(s2, ua.Good, time.Time{}, 0, time.Now(), 0)
	case ua.AttributeIDUserRolePermissions:
		s1 := n.UserRolePermissions(ctx)
		s2 := make([]ua.ExtensionObject, len(s1))
		for i := range s1 {
			s2[i] = s1[i]
		}
		return ua.NewDataValue(s2, ua.Good, time.Time{}, 0, time.Now(), 0)
	default:
		return ua.NewDataValue(nil, ua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
	}
}
