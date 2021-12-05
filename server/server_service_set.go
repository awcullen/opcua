// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"log"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awcullen/opcua"

	"github.com/djherbis/buffer"
	"github.com/google/uuid"
)

// FindServers returns the Servers known to a Server or Discovery Server.
func (srv *Server) findServers(ch *serverSecureChannel, requestid uint32, req *opcua.FindServersRequest) error {
	srvs := make([]opcua.ApplicationDescription, 0, 1)
	for _, s := range []opcua.ApplicationDescription{srv.LocalDescription()} {
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
		&opcua.FindServersResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) getEndpoints(ch *serverSecureChannel, requestid uint32, req *opcua.GetEndpointsRequest) error {
	eps := make([]opcua.EndpointDescription, 0, len(srv.Endpoints()))
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
		&opcua.GetEndpointsResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleCreateSession(ch *serverSecureChannel, requestid uint32, req *opcua.CreateSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
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
		log.Printf("Error verifying EndpointUrl hostname matches certificate hostname.\n")
		// TODO: raise AuditUrlMismatchEventType event
	}
	// check nonce
	switch ch.SecurityPolicyURI() {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256, opcua.SecurityPolicyURIBasic256Sha256:

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
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadCertificateURIInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		if len(req.ClientNonce) < int(nonceLength) {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadNonceInvalid,
					},
				},
				requestid,
			)
			return nil
		}
	default:
	}
	// create server signature
	var serverSignature opcua.SignatureData
	switch ch.SecurityPolicyURI() {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write([]byte(req.ClientCertificate))
		hash.Write([]byte(req.ClientNonce))
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, srv.LocalPrivateKey(), crypto.SHA1, hashed)
		if err != nil {
			return err
		}
		serverSignature = opcua.SignatureData{
			Signature: opcua.ByteString(signature),
			Algorithm: opcua.RsaSha1Signature,
		}

	case opcua.SecurityPolicyURIBasic256Sha256:
		hash := crypto.SHA256.New()
		hash.Write([]byte(req.ClientCertificate))
		hash.Write([]byte(req.ClientNonce))
		hashed := hash.Sum(nil)
		signature, err := rsa.SignPKCS1v15(rand.Reader, srv.LocalPrivateKey(), crypto.SHA256, hashed)
		if err != nil {
			return err
		}
		serverSignature = opcua.SignatureData{
			Signature: opcua.ByteString(signature),
			Algorithm: opcua.RsaSha256Signature,
		}

	default:
		serverSignature = opcua.SignatureData{}
	}

	sessionName := req.SessionName
	if len(sessionName) == 0 {
		sessionName = req.ClientDescription.ApplicationURI
	}

	session := NewSession(
		srv,
		opcua.NewNodeIDOpaque(1, opcua.ByteString(getNextNonce(15))),
		sessionName,
		opcua.NewNodeIDOpaque(0, opcua.ByteString(getNextNonce(nonceLength))),
		opcua.ByteString(getNextNonce(nonceLength)),
		(time.Duration(req.RequestedSessionTimeout) * time.Millisecond),
		req.ClientDescription,
		req.ServerURI,
		req.EndpointURL,
		req.MaxResponseMessageSize,
	)
	err := srv.SessionManager().Add(session)
	if err != nil {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManySessions,
				},
			},
			requestid,
		)
		return nil
	}
	// log.Printf("Created session '%s'.\n", req.SessionName)

	ch.Write(
		&opcua.CreateSessionResponse{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			SessionID:                  session.sessionId,
			AuthenticationToken:        session.authenticationToken,
			RevisedSessionTimeout:      req.RequestedSessionTimeout,
			ServerNonce:                session.sessionNonce,
			ServerCertificate:          opcua.ByteString(srv.LocalCertificate()),
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
func (srv *Server) handleActivateSession(ch *serverSecureChannel, requestid uint32, req *opcua.ActivateSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	m := srv.sessionManager
	session, ok := m.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	// verify the client's signature.
	var err error
	switch ch.SecurityPolicyURI() {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		hash := crypto.SHA1.New()
		hash.Write(srv.LocalCertificate())
		hash.Write([]byte(session.SessionNonce()))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPKCS1v15(ch.RemotePublicKey(), crypto.SHA1, hashed, []byte(req.ClientSignature.Signature))

	case opcua.SecurityPolicyURIBasic256Sha256:
		hash := crypto.SHA256.New()
		hash.Write(srv.LocalCertificate())
		hash.Write([]byte(session.SessionNonce()))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPKCS1v15(ch.RemotePublicKey(), crypto.SHA256, hashed, []byte(req.ClientSignature.Signature))
	}
	if err != nil {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadApplicationSignatureInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	// validate identity and store
	var userIdentity interface{}
	switch userIdentityToken := req.UserIdentityToken.(type) {
	case opcua.IssuedIdentityToken:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == opcua.UserTokenTypeCertificate && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		// TODO:
		userIdentity = opcua.IssuedIdentity{TokenData: userIdentityToken.TokenData}

	case opcua.X509IdentityToken:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == opcua.UserTokenTypeCertificate && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
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
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		userKey, ok := userCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}

		switch secPolicyURI {
		case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
			hash := crypto.SHA1.New()
			hash.Write(srv.LocalCertificate())
			hash.Write([]byte(session.SessionNonce()))
			hashed := hash.Sum(nil)
			err = rsa.VerifyPKCS1v15(userKey, crypto.SHA1, hashed, []byte(req.UserTokenSignature.Signature))

		case opcua.SecurityPolicyURIBasic256Sha256:
			hash := crypto.SHA256.New()
			hash.Write(srv.LocalCertificate())
			hash.Write([]byte(session.SessionNonce()))
			hashed := hash.Sum(nil)
			err = rsa.VerifyPKCS1v15(userKey, crypto.SHA256, hashed, []byte(req.UserTokenSignature.Signature))
		}
		if err != nil {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenRejected,
					},
				},
				requestid,
			)
			return nil
		}
		userIdentity = opcua.X509Identity{Certificate: userIdentityToken.CertificateData}

	case opcua.UserNameIdentityToken:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == opcua.UserTokenTypeUserName && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		if userIdentityToken.UserName == "" {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
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
		case opcua.SecurityPolicyURIBasic128Rsa15:
			if userIdentityToken.EncryptionAlgorithm != opcua.RsaV15KeyWrap {
				ch.Write(
					&opcua.ServiceFault{
						ResponseHeader: opcua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: opcua.BadIdentityTokenInvalid,
						},
					},
					requestid,
				)
				return nil
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf.Write(cipherBytes)
			cipherText := make([]byte, int32(len(ch.LocalPrivateKey().D.Bytes())))
			for cipherBuf.Len() > 0 {
				cipherBuf.Read(cipherText)
				// decrypt with local private key.
				plainText, err := rsa.DecryptPKCS1v15(rand.Reader, ch.LocalPrivateKey(), cipherText)
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
					&opcua.ServiceFault{
						ResponseHeader: opcua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: opcua.BadIdentityTokenRejected,
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
			userIdentity = opcua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(passwordBytes)}

		case opcua.SecurityPolicyURIBasic256, opcua.SecurityPolicyURIBasic256Sha256:
			if userIdentityToken.EncryptionAlgorithm != opcua.RsaOaepKeyWrap {
				ch.Write(
					&opcua.ServiceFault{
						ResponseHeader: opcua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: opcua.BadIdentityTokenInvalid,
						},
					},
					requestid,
				)
				return nil
			}
			plainBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf := buffer.NewPartitionAt(bufferPool)
			cipherBuf.Write(cipherBytes)
			cipherText := make([]byte, int32(len(ch.LocalPrivateKey().D.Bytes())))
			for cipherBuf.Len() > 0 {
				cipherBuf.Read(cipherText)
				// decrypt with local private key.
				plainText, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, ch.LocalPrivateKey(), cipherText, []byte{})
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
					&opcua.ServiceFault{
						ResponseHeader: opcua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: opcua.BadIdentityTokenRejected,
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
			userIdentity = opcua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(passwordBytes)}

		default:
			userIdentity = opcua.UserNameIdentity{UserName: userIdentityToken.UserName, Password: string(cipherBytes)}

		}

	case opcua.AnonymousIdentityToken:
		var tokenPolicy *opcua.UserTokenPolicy
		for _, t := range ch.LocalEndpoint().UserIdentityTokens {
			if t.TokenType == opcua.UserTokenTypeAnonymous && t.PolicyID == userIdentityToken.PolicyID {
				tokenPolicy = &t
				break
			}
		}
		if tokenPolicy == nil {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadIdentityTokenInvalid,
					},
				},
				requestid,
			)
			return nil
		}
		userIdentity = opcua.AnonymousIdentity{}

	}

	// authenticate user
	switch id := userIdentity.(type) {
	case opcua.AnonymousIdentity:
		err = nil

	case opcua.UserNameIdentity:
		if auth := srv.userNameIdentityAuthenticator; auth != nil {
			err = auth.AuthenticateUserNameIdentity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = opcua.BadUserAccessDenied
		}

	case opcua.X509Identity:
		if auth := srv.x509IdentityAuthenticator; auth != nil {
			err = auth.AuthenticateX509Identity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = opcua.BadUserAccessDenied
		}

	case opcua.IssuedIdentity:
		if auth := srv.issuedIdentityAuthenticator; auth != nil {
			err = auth.AuthenticateIssuedIdentity(id, ch.remoteApplicationURI, ch.localEndpoint.EndpointURL)
		} else {
			err = opcua.BadUserAccessDenied
		}

	default:
		err = opcua.BadUserAccessDenied

	}
	if err != nil {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadUserAccessDenied,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadUserAccessDenied,
				},
			},
			requestid,
		)
		return nil
	}

	session.SetUserIdentity(userIdentity)
	session.SetUserRoles(userRoles)
	session.SetSessionNonce(opcua.ByteString(getNextNonce(nonceLength)))
	session.SetSecureChannelId(ch.ChannelID())
	session.localeIds = req.LocaleIDs

	ch.Write(
		&opcua.ActivateSessionResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleCloseSession(ch *serverSecureChannel, requestid uint32, req *opcua.CloseSessionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.sessionManager.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
		&opcua.CloseSessionResponse{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
		},
		requestid,
	)
	return nil
}

// handleCancel cancels a request.
func (srv *Server) handleCancel(ch *serverSecureChannel, requestid uint32, req *opcua.CancelRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.sessionManager.Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
				},
			},
			requestid,
		)
		return nil
	}
	if id != ch.ChannelID() {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	ch.Write(
		&opcua.CancelResponse{
			ResponseHeader: opcua.ResponseHeader{
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

func (srv *Server) handleBrowse(ch *serverSecureChannel, requestid uint32, req *opcua.BrowseRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadViewIDUnknown,
					},
				},
				requestid,
			)
			session.browseErrorCount++
			session.errorCount++
			return nil
		}
		if n.NodeClass() != opcua.NodeClassView {
			ch.Write(
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadViewIDUnknown,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.browseErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]opcua.BrowseResult, l)
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
			if d.BrowseDirection < opcua.BrowseDirectionForward || d.BrowseDirection > opcua.BrowseDirectionBoth {
				results[i] = opcua.BrowseResult{StatusCode: opcua.BadBrowseDirectionInvalid}
				wg.Done()
				return
			}
			m := srv.NamespaceManager()
			node, ok := m.FindNode(d.NodeID)
			if !ok {
				results[i] = opcua.BrowseResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp := node.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
				results[i] = opcua.BrowseResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			both := d.BrowseDirection == opcua.BrowseDirectionBoth
			isInverse := d.BrowseDirection == opcua.BrowseDirectionInverse
			allTypes := d.ReferenceTypeID == nil
			allClasses := d.NodeClassMask == 0
			if !allTypes {
				rt, ok := m.FindNode(d.ReferenceTypeID)
				if !ok {
					results[i] = opcua.BrowseResult{StatusCode: opcua.BadReferenceTypeIDInvalid}
					wg.Done()
					return
				}
				if rt.NodeClass() != opcua.NodeClassReferenceType {
					results[i] = opcua.BrowseResult{StatusCode: opcua.BadReferenceTypeIDInvalid}
					wg.Done()
					return
				}
			}
			refs := node.References()
			rds := make([]opcua.ReferenceDescription, 0, len(refs))
			for _, r := range refs {
				if !(both || r.IsInverse == isInverse) {
					continue
				}
				if !(allTypes || d.ReferenceTypeID == r.ReferenceTypeID || (d.IncludeSubtypes && m.IsSubtype(r.ReferenceTypeID, d.ReferenceTypeID))) {
					continue
				}
				t, ok := m.FindNode(opcua.ToNodeID(r.TargetID, srv.NamespaceUris()))
				if !ok {
					results[i] = opcua.BrowseResult{StatusCode: opcua.BadNodeIDUnknown}
					wg.Done()
					return
				}
				rp2 := t.UserRolePermissions(ctx)
				if !IsUserPermitted(rp2, opcua.PermissionTypeBrowse) {
					continue
				}
				if !(allClasses || d.NodeClassMask&uint32(t.NodeClass()) != 0) {
					continue
				}
				var rt opcua.NodeID
				if d.ResultMask&uint32(opcua.BrowseResultMaskReferenceTypeID) != 0 {
					rt = r.ReferenceTypeID
				}
				fo := false
				if d.ResultMask&uint32(opcua.BrowseResultMaskIsForward) != 0 {
					fo = !r.IsInverse
				}
				nc := opcua.NodeClassUnspecified
				if d.ResultMask&uint32(opcua.BrowseResultMaskNodeClass) != 0 {
					nc = t.NodeClass()
				}
				bn := opcua.QualifiedName{}
				if d.ResultMask&uint32(opcua.BrowseResultMaskBrowseName) != 0 {
					bn = t.BrowseName()
				}
				dn := opcua.LocalizedText{}
				if d.ResultMask&uint32(opcua.BrowseResultMaskDisplayName) != 0 {
					dn = t.DisplayName()
				}
				var td opcua.ExpandedNodeID
				if d.ResultMask&uint32(opcua.BrowseResultMaskTypeDefinition) != 0 {
					if nc := t.NodeClass(); nc == opcua.NodeClassObject || nc == opcua.NodeClassVariable {
						hasTypeDef := opcua.ReferenceTypeIDHasTypeDefinition
						for _, tr := range t.References() {
							if hasTypeDef == tr.ReferenceTypeID {
								td = tr.TargetID
								break
							}
						}
					}
				}
				rds = append(rds, opcua.ReferenceDescription{
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
					results[i] = opcua.BrowseResult{
						StatusCode: opcua.BadNoContinuationPoints,
					}
					wg.Done()
					return
				}
				results[i] = opcua.BrowseResult{
					ContinuationPoint: opcua.ByteString(cp),
					References:        rds[:max],
				}
				wg.Done()
				return
			}

			results[i] = opcua.BrowseResult{
				References: rds,
			}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&opcua.BrowseResponse{
				ResponseHeader: opcua.ResponseHeader{
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

func (srv *Server) handleBrowseNext(ch *serverSecureChannel, requestid uint32, req *opcua.BrowseNextRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.browseNextErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]opcua.BrowseResult, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			cp := req.ContinuationPoints[i]
			if len(cp) == 0 {
				results[i] = opcua.BrowseResult{
					StatusCode: opcua.Good,
				}
				wg.Done()
				return
			}
			rds, max, ok := session.removeBrowseContinuationPoint([]byte(cp))
			if !ok {
				results[i] = opcua.BrowseResult{
					StatusCode: opcua.BadContinuationPointInvalid,
				}
				wg.Done()
				return
			}
			if req.ReleaseContinuationPoints {
				results[i] = opcua.BrowseResult{
					StatusCode: 0,
				}
				wg.Done()
				return
			}
			if len(rds) > max {
				cp, err := session.addBrowseContinuationPoint(rds[max:], max)
				if err != nil {
					results[i] = opcua.BrowseResult{
						StatusCode: opcua.BadNoContinuationPoints,
					}
					wg.Done()
					return
				}
				results[i] = opcua.BrowseResult{
					ContinuationPoint: opcua.ByteString(cp),
					References:        rds[:max],
				}
				wg.Done()
				return
			}
			results[i] = opcua.BrowseResult{
				References: rds,
			}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&opcua.BrowseNextResponse{
				ResponseHeader: opcua.ResponseHeader{
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

func (srv *Server) handleTranslateBrowsePathsToNodeIds(ch *serverSecureChannel, requestid uint32, req *opcua.TranslateBrowsePathsToNodeIDsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.translateBrowsePathsToNodeIdsErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]opcua.BrowsePathResult, l)

	// handle requests in parallel using server thread pool.
	wp := srv.WorkerPool()
	wg := sync.WaitGroup{}
	wg.Add(l)

	for ii := 0; ii < l; ii++ {
		i := ii
		wp.Submit(func() {
			d := req.BrowsePaths[i]
			if len(d.RelativePath.Elements) == 0 {
				results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNothingToDo, Targets: []opcua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			for _, element := range d.RelativePath.Elements {
				if element.TargetName.Name == "" {
					results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadBrowseNameInvalid, Targets: []opcua.BrowsePathTarget{}}
					wg.Done()
					return
				}
			}
			targets, err1 := srv.follow(d.StartingNode, d.RelativePath.Elements)
			if err1 == opcua.BadNodeIDUnknown {
				results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNodeIDUnknown, Targets: []opcua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if err1 == opcua.BadNothingToDo {
				results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNothingToDo, Targets: []opcua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if err1 == opcua.BadNoMatch {
				results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNoMatch, Targets: []opcua.BrowsePathTarget{}}
				wg.Done()
				return
			}
			if targets != nil {
				if len(targets) > 0 {
					results[i] = opcua.BrowsePathResult{StatusCode: opcua.Good, Targets: targets}
					wg.Done()
					return
				}
				results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNoMatch, Targets: targets}
				wg.Done()
				return
			}
			results[i] = opcua.BrowsePathResult{StatusCode: opcua.BadNoMatch, Targets: []opcua.BrowsePathTarget{}}
			wg.Done()
		})
	}

	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&opcua.TranslateBrowsePathsToNodeIDsResponse{
				ResponseHeader: opcua.ResponseHeader{
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

func (srv *Server) handleRegisterNodes(ch *serverSecureChannel, requestid uint32, req *opcua.RegisterNodesRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.registerNodesErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]opcua.NodeID, l)

	for ii := 0; ii < l; ii++ {
		results[ii] = req.NodesToRegister[ii]
	}

	ch.Write(
		&opcua.RegisterNodesResponse{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			RegisteredNodeIDs: results,
		},
		requestid,
	)
	return nil
}

func (srv *Server) handleUnregisterNodes(ch *serverSecureChannel, requestid uint32, req *opcua.UnregisterNodesRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.unregisterNodesErrorCount++
		session.errorCount++
		return nil
	}

	ch.Write(
		&opcua.UnregisterNodesResponse{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
		},
		requestid,
	)
	return nil
}

func (srv *Server) follow(nodeID opcua.NodeID, elements []opcua.RelativePathElement) ([]opcua.BrowsePathTarget, error) {
	if len(elements) == 0 {
		return nil, opcua.BadNothingToDo
	} else if len(elements) == 1 {
		ns, err2 := srv.target(nodeID, elements[0])
		if err2 != nil {
			return nil, err2
		}
		targets := make([]opcua.BrowsePathTarget, len(ns))
		for i, n := range ns {
			targets[i] = opcua.BrowsePathTarget{TargetID: n, RemainingPathIndex: math.MaxUint32}
		}
		return targets, nil
	} else {
		e := elements[0]
		ns2, err3 := srv.target(nodeID, e)
		if err3 != nil {
			return nil, err3
		}
		var nextID opcua.ExpandedNodeID
		if len(ns2) > 0 {
			nextID = ns2[0]
		}
		nextElements := make([]opcua.RelativePathElement, len(elements)-1)
		copy(nextElements, elements[1:])
		nextNode, ok := srv.NamespaceManager().FindNode(opcua.ToNodeID(nextID, srv.NamespaceUris()))
		if ok {
			return srv.follow(nextNode.NodeID(), nextElements)
		}
		if len(nextElements) == 0 {
			return []opcua.BrowsePathTarget{
				{TargetID: nextID, RemainingPathIndex: math.MaxUint32},
			}, nil
		}
		return []opcua.BrowsePathTarget{
			{TargetID: nextID, RemainingPathIndex: uint32(len(nextElements))},
		}, nil
	}
}

// target returns a slice of target nodeid's that match the given RelativePathElement
func (srv *Server) target(nodeID opcua.NodeID, element opcua.RelativePathElement) ([]opcua.ExpandedNodeID, error) {
	referenceTypeID := element.ReferenceTypeID
	includeSubtypes := element.IncludeSubtypes
	isInverse := element.IsInverse
	targetName := element.TargetName
	m := srv.NamespaceManager()
	node, ok := m.FindNode(nodeID)
	if !ok {
		return nil, opcua.BadNodeIDUnknown
	}
	refs := node.References()
	targets := make([]opcua.ExpandedNodeID, 0, 4)
	for _, r := range refs {
		if !(r.IsInverse == isInverse) {
			continue
		}
		if !(referenceTypeID == nil || r.ReferenceTypeID == referenceTypeID || (includeSubtypes && m.IsSubtype(r.ReferenceTypeID, referenceTypeID))) {
			continue
		}
		t, ok := m.FindNode(opcua.ToNodeID(r.TargetID, srv.NamespaceUris()))
		if !ok {
			continue
		}
		if !(targetName == t.BrowseName()) {
			continue
		}
		targets = append(targets, r.TargetID)
	}
	if len(targets) == 0 {
		return nil, opcua.BadNoMatch
	}
	return targets, nil
}

// Read returns a list of Node attributes.
func (srv *Server) handleRead(ch *serverSecureChannel, requestid uint32, req *opcua.ReadRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadMaxAgeInvalid,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}
	// check TimestampsToReturn
	if req.TimestampsToReturn < opcua.TimestampsToReturnSource || req.TimestampsToReturn > opcua.TimestampsToReturnNeither {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTimestampsToReturnInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.readErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.DataValue, l)
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
			&opcua.ReadResponse{
				ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleWrite(ch *serverSecureChannel, requestid uint32, req *opcua.WriteRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.writeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.StatusCode, l)

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
			&opcua.WriteResponse{
				ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleHistoryRead(ch *serverSecureChannel, requestid uint32, req *opcua.HistoryReadRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
	if req.TimestampsToReturn < opcua.TimestampsToReturnSource || req.TimestampsToReturn > opcua.TimestampsToReturnBoth {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadInvalidTimestampArgument,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadHistoryOperationUnsupported,
				},
			},
			requestid,
		)
		return nil
	}

	switch details := req.HistoryReadDetails.(type) {
	case opcua.ReadEventDetails:
		results, status := h.ReadEvent(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&opcua.HistoryReadResponse{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case opcua.ReadRawModifiedDetails:
		results, status := h.ReadRawModified(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&opcua.HistoryReadResponse{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case opcua.ReadProcessedDetails:
		results, status := h.ReadProcessed(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&opcua.HistoryReadResponse{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
					ServiceResult: status,
				},
				Results: results,
			},
			requestid,
		)
		return nil

	case opcua.ReadAtTimeDetails:
		results, status := h.ReadAtTime(ctx, req.NodesToRead, details, req.TimestampsToReturn, req.ReleaseContinuationPoints)
		ch.Write(
			&opcua.HistoryReadResponse{
				ResponseHeader: opcua.ResponseHeader{
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
		&opcua.ServiceFault{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHandle,
				ServiceResult: opcua.BadHistoryOperationInvalid,
			},
		},
		requestid,
	)
	return nil
}

// readRange returns slice of value specified by IndexRange
func readRange(source opcua.DataValue, indexRange string) opcua.DataValue {
	if indexRange == "" {
		return source
	}
	ranges := strings.Split(indexRange, ",")
	switch src := source.Value.(type) {
	case string:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		v1 := []rune(src)
		i, j, status := parseBounds(ranges[0], len(v1))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]rune, j-i)
		copy(dst, v1[i:j])
		return opcua.NewDataValue(string(dst), source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case opcua.ByteString:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		v1 := []byte(src)
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]byte, j-i)
		copy(dst, v1[i:j])
		return opcua.NewDataValue(opcua.ByteString(dst), source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []bool:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]bool, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int8:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int8, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []byte:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]byte, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int16:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int16, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint16:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint16, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int32:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int32, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint32:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint32, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []int64:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]int64, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uint64:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uint64, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []float32:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]float32, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []float64:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]float64, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []string:
		if len(ranges) > 2 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]string, j-i)
		copy(dst, src[i:j])
		if len(ranges) > 1 {
			for ii := range dst {
				v1 := []rune(dst[ii])
				i, j, status := parseBounds(ranges[1], len(v1))
				if status.IsBad() {
					return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
				}
				dst2 := make([]rune, j-i)
				copy(dst2, v1[i:j])
				dst[ii] = string(dst2)
			}
		}
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []time.Time:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]time.Time, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []uuid.UUID:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]uuid.UUID, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.ByteString:
		if len(ranges) > 2 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.ByteString, j-i)
		copy(dst, src[i:j])
		if len(ranges) > 1 {
			for ii := range dst {
				i, j, status := parseBounds(ranges[1], len(dst[ii]))
				if status.IsBad() {
					return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
				}
				dst2 := make([]byte, j-i)
				copy(dst2, dst[ii][i:j])
				dst[ii] = opcua.ByteString(dst2)
			}
		}
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.XMLElement:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.XMLElement, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.NodeID:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.NodeID, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.ExpandedNodeID:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.ExpandedNodeID, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.StatusCode:
		i, j, status := parseBounds(ranges[0], len(src))
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.StatusCode, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.QualifiedName:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.QualifiedName, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.LocalizedText:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.LocalizedText, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.ExtensionObject:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.ExtensionObject, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.DataValue:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.DataValue, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.Variant:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.Variant, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	case []opcua.DiagnosticInfo:
		if len(ranges) > 1 {
			return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NewDataValue(nil, status, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
		}
		dst := make([]opcua.DiagnosticInfo, j-i)
		copy(dst, src[i:j])
		return opcua.NewDataValue(dst, source.StatusCode, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	default:
		return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, source.SourceTimestamp, 0, source.ServerTimestamp, 0)
	}
}

// writeRange sets subset of value specified by IndexRange
func writeRange(source opcua.DataValue, value opcua.DataValue, indexRange string) (opcua.DataValue, opcua.StatusCode) {
	if indexRange == "" {
		return opcua.NewDataValue(value.Value, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	}
	ranges := strings.Split(indexRange, ",")
	switch src := source.Value.(type) {
	case string:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		v1 := []rune(src)
		i, j, status := parseBounds(ranges[0], len(v1))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := []rune(value.Value.(string))
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]rune, len(v1))
		copy(dst, v1)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(string(dst), value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case opcua.ByteString:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.(opcua.ByteString)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]byte, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(opcua.ByteString(dst), value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []bool:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]bool)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]bool, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []int8:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]int8)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]int8, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []byte:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]byte)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]byte, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []int16:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]int16)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]int16, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []uint16:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]uint16)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]uint16, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []int32:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]int32)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]int32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []uint32:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]uint32)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]uint32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []int64:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]int64)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]int64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []uint64:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]uint64)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]uint64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []float32:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]float32)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]float32, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []float64:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]float64)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]float64, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []string:
		if len(ranges) > 2 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]string)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]string, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []time.Time:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]time.Time)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]time.Time, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []uuid.UUID:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]uuid.UUID)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]uuid.UUID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.ByteString:
		if len(ranges) > 2 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.ByteString)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.ByteString, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.XMLElement:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.XMLElement)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.XMLElement, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.NodeID:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.NodeID)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.NodeID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.ExpandedNodeID:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.ExpandedNodeID)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.ExpandedNodeID, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.StatusCode:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.StatusCode)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.StatusCode, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.QualifiedName:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.QualifiedName)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.QualifiedName, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.LocalizedText:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.LocalizedText)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.LocalizedText, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.ExtensionObject:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.ExtensionObject)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.ExtensionObject, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.DataValue:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.DataValue)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.DataValue, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.Variant:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.Variant)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.Variant, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	case []opcua.DiagnosticInfo:
		if len(ranges) > 1 {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		i, j, status := parseBounds(ranges[0], len(src))
		if status.IsBad() {
			return opcua.NilDataValue, status
		}
		v2 := value.Value.([]opcua.DiagnosticInfo)
		if j-i != len(v2) {
			return opcua.NilDataValue, opcua.BadIndexRangeNoData
		}
		dst := make([]opcua.DiagnosticInfo, len(src))
		copy(dst, src)
		copy(dst[i:j], v2)
		return opcua.NewDataValue(dst, value.StatusCode, time.Now(), 0, time.Now(), 0), opcua.Good
	default:
		return opcua.NilDataValue, opcua.BadIndexRangeNoData
	}
}

func parseBounds(s string, length int) (int, int, opcua.StatusCode) {
	lo := int64(-1)
	hi := int64(-1)
	len := int64(length)
	var err error

	if len == 0 {
		return -1, -1, opcua.BadIndexRangeNoData
	}

	if s == "" {
		return 0, length, opcua.Good
	}

	index := strings.Index(s, ":")
	if index != -1 {
		lo, err = strconv.ParseInt(s[:index], 10, 32)
		if err != nil {
			return -1, -1, opcua.BadIndexRangeInvalid
		}
		hi, err = strconv.ParseInt(s[index+1:], 10, 32)
		if err != nil {
			return -1, -1, opcua.BadIndexRangeInvalid
		}
		if hi < 0 {
			return -1, -1, opcua.BadIndexRangeInvalid
		}
		if lo >= hi {
			return -1, -1, opcua.BadIndexRangeInvalid
		}
	} else {
		lo, err = strconv.ParseInt(s, 10, 32)
		if err != nil {
			return -1, -1, opcua.BadIndexRangeInvalid
		}
	}
	if lo < 0 {
		return -1, -1, opcua.BadIndexRangeInvalid
	}
	// now check if no data in range
	if lo >= len {
		return -1, -1, opcua.BadIndexRangeNoData
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

	return int(lo), int(hi), opcua.Good
}

// selectTimestamps returns new instances of DataValue with only the selected timestamps.
func selectTimestamps(values []opcua.DataValue, timestampsToReturn opcua.TimestampsToReturn) []opcua.DataValue {
	switch timestampsToReturn {
	case opcua.TimestampsToReturnSource:
		for i, value := range values {
			values[i] = opcua.NewDataValue(value.Value, value.StatusCode, value.SourceTimestamp, 0, time.Time{}, 0)
		}
		return values
	case opcua.TimestampsToReturnServer:
		for i, value := range values {
			values[i] = opcua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, value.ServerTimestamp, 0)
		}
		return values
	case opcua.TimestampsToReturnNeither:
		for i, value := range values {
			values[i] = opcua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, time.Time{}, 0)
		}
		return values
	default:
		return values
	}
}

// Call invokes a list of Methods.
func (srv *Server) handleCall(ch *serverSecureChannel, requestid uint32, req *opcua.CallRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.callErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.CallMethodResult, l)

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
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp := n1.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			switch n1.(type) {
			case *ObjectNode:
			case *ObjectTypeNode:
			default:
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNodeClassInvalid}
				wg.Done()
				return
			}
			n2, ok := m.FindNode(n.MethodID)
			if !ok {
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			rp = n2.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNodeIDUnknown}
				wg.Done()
				return
			}
			// TODO: check if method is hasComponent of object or objectType
			switch n3 := n2.(type) {
			case *MethodNode:
				if !n3.UserExecutable(ctx) {
					results[i] = opcua.CallMethodResult{StatusCode: opcua.BadUserAccessDenied}
				} else {
					if n3.callMethodHandler != nil {
						results[i] = n3.callMethodHandler(ctx, n)
					} else {
						results[i] = opcua.CallMethodResult{StatusCode: opcua.BadNotImplemented}
					}
				}
			default:
				results[i] = opcua.CallMethodResult{StatusCode: opcua.BadAttributeIDInvalid}
			}
			wg.Done()
		})
	}
	go func() {
		// wait until all tasks are done
		wg.Wait()
		ch.Write(
			&opcua.CallResponse{
				ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleCreateMonitoredItems(ch *serverSecureChannel, requestid uint32, req *opcua.CreateMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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

	if req.TimestampsToReturn < opcua.TimestampsToReturnSource || req.TimestampsToReturn > opcua.TimestampsToReturnNeither {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTimestampsToReturnInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.createMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.MonitoredItemCreateResult, l)
	minSupportedSampleRate := srv.ServerCapabilities().MinSupportedSampleRate
	for i, item := range req.ItemsToCreate {
		n, ok := srv.NamespaceManager().FindNode(item.ItemToMonitor.NodeID)
		if !ok {
			results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadNodeIDUnknown}
			continue
		}
		attr := item.ItemToMonitor.AttributeID
		if !n.IsAttributeIDValid(attr) {
			results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadAttributeIDInvalid}
			continue
		}
		switch attr {
		case opcua.AttributeIDValue:
			n2, ok := n.(*VariableNode)
			if !ok {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadAttributeIDInvalid}
				continue
			}
			// check AccessLevel
			if (n2.AccessLevel() & opcua.AccessLevelsCurrentRead) == 0 {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadNotReadable}
				continue
			}
			if (n2.UserAccessLevel(ctx) & opcua.AccessLevelsCurrentRead) == 0 {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadUserAccessDenied}
				continue
			}
			if sc := srv.validateIndexRange(ctx, item.ItemToMonitor.IndexRange, n2.DataType(), n2.ValueRank()); sc != opcua.Good {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: sc}
				continue
			}
			if item.RequestedParameters.Filter == nil {
				item.RequestedParameters.Filter = opcua.DataChangeFilter{Trigger: opcua.DataChangeTriggerStatusValue}
			}
			dcf, ok := item.RequestedParameters.Filter.(opcua.DataChangeFilter)
			if !ok {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadFilterNotAllowed}
				continue
			}
			if dcf.DeadbandType != uint32(opcua.DeadbandTypeNone) {
				destType := srv.NamespaceManager().FindVariantType(n2.DataType())
				switch destType {
				case opcua.VariantTypeByte, opcua.VariantTypeSByte:
				case opcua.VariantTypeInt16, opcua.VariantTypeInt32, opcua.VariantTypeInt64:
				case opcua.VariantTypeUInt16, opcua.VariantTypeUInt32, opcua.VariantTypeUInt64:
				case opcua.VariantTypeFloat, opcua.VariantTypeDouble:
				default:
					results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadFilterNotAllowed}
					continue
				}
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, minSupportedSampleRate)
			sub.AppendItem(mi)
			results[i] = opcua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		case opcua.AttributeIDEventNotifier:
			n2, ok := n.(*ObjectNode)
			if !ok {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadAttributeIDInvalid}
				continue
			}
			// check EventNotifier
			if (n2.EventNotifier() & opcua.EventNotifierSubscribeToEvents) == 0 {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadNotReadable}
				continue
			}
			rp := n2.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, opcua.PermissionTypeReceiveEvents) {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadUserAccessDenied}
				continue
			}
			if item.RequestedParameters.Filter == nil {
				item.RequestedParameters.Filter = opcua.EventFilter{} // TODO: get EventBase select clause
			}
			_, ok = item.RequestedParameters.Filter.(opcua.EventFilter)
			if !ok {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadFilterNotAllowed}
				continue
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, 0.0)
			sub.AppendItem(mi)
			results[i] = opcua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		default:
			rp := n.UserRolePermissions(ctx)
			if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadAttributeIDInvalid}
				continue
			}
			if item.RequestedParameters.Filter != nil {
				results[i] = opcua.MonitoredItemCreateResult{StatusCode: opcua.BadFilterNotAllowed}
				continue
			}
			mi := NewMonitoredItem(ctx, sub, n, item.ItemToMonitor, item.MonitoringMode, item.RequestedParameters, req.TimestampsToReturn, minSupportedSampleRate)
			sub.AppendItem(mi)
			results[i] = opcua.MonitoredItemCreateResult{
				MonitoredItemID:         mi.id,
				RevisedSamplingInterval: mi.samplingInterval,
				RevisedQueueSize:        mi.queueSize,
			}
			continue
		}
	}

	ch.Write(
		&opcua.CreateMonitoredItemsResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleModifyMonitoredItems(ch *serverSecureChannel, requestid uint32, req *opcua.ModifyMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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

	if req.TimestampsToReturn < opcua.TimestampsToReturnSource || req.TimestampsToReturn > opcua.TimestampsToReturnNeither {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTimestampsToReturnInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.modifyMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.MonitoredItemModifyResult, l)

	for i, modifyReq := range req.ItemsToModify {
		if item, ok := sub.FindItem(modifyReq.MonitoredItemID); ok {
			attr := item.itemToMonitor.AttributeID
			switch {
			case attr == opcua.AttributeIDValue:
				if modifyReq.RequestedParameters.Filter == nil {
					modifyReq.RequestedParameters.Filter = opcua.DataChangeFilter{Trigger: opcua.DataChangeTriggerStatusValue}
				}
				dcf, ok := modifyReq.RequestedParameters.Filter.(opcua.DataChangeFilter)
				if !ok {
					results[i] = opcua.MonitoredItemModifyResult{StatusCode: opcua.BadFilterNotAllowed}
					continue
				}
				if dcf.DeadbandType != uint32(opcua.DeadbandTypeNone) {
					destType := srv.NamespaceManager().FindVariantType(item.node.(*VariableNode).DataType())
					switch destType {
					case opcua.VariantTypeByte, opcua.VariantTypeSByte:
					case opcua.VariantTypeInt16, opcua.VariantTypeInt32, opcua.VariantTypeInt64:
					case opcua.VariantTypeUInt16, opcua.VariantTypeUInt32, opcua.VariantTypeUInt64:
					case opcua.VariantTypeFloat, opcua.VariantTypeDouble:
					default:
						results[i] = opcua.MonitoredItemModifyResult{StatusCode: opcua.BadFilterNotAllowed}
						continue
					}
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			case attr == opcua.AttributeIDEventNotifier:
				if modifyReq.RequestedParameters.Filter == nil {
					modifyReq.RequestedParameters.Filter = opcua.EventFilter{} // TODO: get EventBase select clause
				}
				_, ok := modifyReq.RequestedParameters.Filter.(opcua.EventFilter)
				if !ok {
					results[i] = opcua.MonitoredItemModifyResult{StatusCode: opcua.BadFilterNotAllowed}
					continue
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			default:
				if modifyReq.RequestedParameters.Filter != nil {
					results[i] = opcua.MonitoredItemModifyResult{StatusCode: opcua.BadFilterNotAllowed}
					continue
				}
				results[i] = item.Modify(ctx, modifyReq)
				continue
			}
		} else {
			results[i] = opcua.MonitoredItemModifyResult{StatusCode: opcua.BadMonitoredItemIDInvalid}
		}
	}

	ch.Write(
		&opcua.ModifyMonitoredItemsResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleSetMonitoringMode(ch *serverSecureChannel, requestid uint32, req *opcua.SetMonitoringModeRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.setMonitoringModeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.StatusCode, l)

	for i, id := range req.MonitoredItemIDs {
		if item, ok := sub.FindItem(id); ok {
			item.SetMonitoringMode(ctx, req.MonitoringMode)
			results[i] = opcua.Good
		} else {
			results[i] = opcua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&opcua.SetMonitoringModeResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleSetTriggering(ch *serverSecureChannel, requestid uint32, req *opcua.SetTriggeringRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadMonitoredItemIDInvalid,
				},
			},
			requestid,
		)
		session.setTriggeringErrorCount++
		session.errorCount++
		return nil
	}

	removeResults := make([]opcua.StatusCode, len(req.LinksToRemove))
	for i, link := range req.LinksToRemove {
		triggered, ok := sub.FindItem(link)
		if !ok {
			removeResults[i] = opcua.BadMonitoredItemIDInvalid
			continue
		}
		if trigger.RemoveTriggeredItem(triggered) {
			removeResults[i] = opcua.Good
		} else {
			removeResults[i] = opcua.BadMonitoredItemIDInvalid
		}
	}

	addResults := make([]opcua.StatusCode, len(req.LinksToAdd))
	for i, link := range req.LinksToAdd {
		triggered, ok := sub.FindItem(link)
		if !ok {
			addResults[i] = opcua.BadMonitoredItemIDInvalid
			continue
		}
		if trigger.AddTriggeredItem(triggered) {
			addResults[i] = opcua.Good
		} else {
			addResults[i] = opcua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&opcua.SetTriggeringResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleDeleteMonitoredItems(ch *serverSecureChannel, requestid uint32, req *opcua.DeleteMonitoredItemsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManyOperations,
				},
			},
			requestid,
		)
		session.deleteMonitoredItemsErrorCount++
		session.errorCount++
		return nil
	}
	results := make([]opcua.StatusCode, l)

	for i, id := range req.MonitoredItemIDs {
		if ok := sub.DeleteItem(ctx, id); ok {
			results[i] = opcua.Good
		} else {
			results[i] = opcua.BadMonitoredItemIDInvalid
		}
	}

	ch.Write(
		&opcua.DeleteMonitoredItemsResponse{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHeader.RequestHandle,
			},
			Results: results,
		},
		requestid,
	)
	return nil
}

func (srv *Server) validateIndexRange(ctx context.Context, s string, dataType opcua.NodeID, rank int32) opcua.StatusCode {
	lo := int64(-1)
	hi := int64(-1)
	var err error

	if s == "" {
		return opcua.Good
	}

	ranges := strings.Split(s, ",")
	for _, r := range ranges {
		index := strings.Index(r, ":")
		if index != -1 {
			lo, err = strconv.ParseInt(r[:index], 10, 32)
			if err != nil {
				return opcua.BadIndexRangeInvalid
			}
			hi, err = strconv.ParseInt(r[index+1:], 10, 32)
			if err != nil {
				return opcua.BadIndexRangeInvalid
			}
			if hi < 0 {
				return opcua.BadIndexRangeInvalid
			}
			if lo >= hi {
				return opcua.BadIndexRangeInvalid
			}
		} else {
			lo, err = strconv.ParseInt(r, 10, 32)
			if err != nil {
				return opcua.BadIndexRangeInvalid
			}
		}
		if lo < 0 {
			return opcua.BadIndexRangeInvalid
		}
	}

	destType := srv.NamespaceManager().FindVariantType(dataType)

	switch rank {
	case opcua.ValueRankScalarOrOneDimension:
		diff := len(ranges) - 1
		if !(diff == 0) {
			if !(diff == 1 && (destType == opcua.VariantTypeString || destType == opcua.VariantTypeByteString)) {
				return opcua.BadIndexRangeNoData
			}
		}
	case opcua.ValueRankAny:
	case opcua.ValueRankScalar:
		if !(len(ranges) == 1 && (destType == opcua.VariantTypeString || destType == opcua.VariantTypeByteString)) {
			return opcua.BadIndexRangeNoData
		}
	case opcua.ValueRankOneOrMoreDimensions:
	default:
		diff := len(ranges) - int(rank)
		if !(diff == 0) {
			if !(diff == 1 && (destType == opcua.VariantTypeString || destType == opcua.VariantTypeByteString)) {
				return opcua.BadIndexRangeNoData
			}
		}
	}

	return opcua.Good
}

// CreateSubscription creates a Subscription.
func (srv *Server) handleCreateSubscription(ch *serverSecureChannel, requestid uint32, req *opcua.CreateSubscriptionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadTooManySubscriptions,
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
		&opcua.CreateSubscriptionResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleModifySubscription(ch *serverSecureChannel, requestid uint32, req *opcua.ModifySubscriptionRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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
		&opcua.ModifySubscriptionResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleSetPublishingMode(ch *serverSecureChannel, requestid uint32, req *opcua.SetPublishingModeRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		session.setPublishingModeErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.StatusCode, len(req.SubscriptionIDs))
	sm := srv.SubscriptionManager()
	for i, id := range req.SubscriptionIDs {
		s, ok := sm.Get(id)
		if ok {
			s.SetPublishingMode(req.PublishingEnabled)
			results[i] = opcua.Good
		} else {
			results[i] = opcua.BadSubscriptionIDInvalid
		}
	}
	ch.Write(
		&opcua.SetPublishingModeResponse{
			ResponseHeader: opcua.ResponseHeader{
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
func (srv *Server) handleDeleteSubscriptions(ch *serverSecureChannel, requestid uint32, req *opcua.DeleteSubscriptionsRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
				},
			},
			requestid,
		)
		return nil
	}

	l := len(req.SubscriptionIDs)
	if l == 0 {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNothingToDo,
				},
			},
			requestid,
		)
		session.deleteSubscriptionsErrorCount++
		session.errorCount++
		return nil
	}

	results := make([]opcua.StatusCode, l)
	sm := srv.SubscriptionManager()
	for i, id := range req.SubscriptionIDs {
		if s, ok := sm.Get(id); ok {
			sm.Delete(s)
			s.Delete()
			// log.Printf("Deleted subscription '%d'.\n", id)
			results[i] = opcua.Good
		} else {
			results[i] = opcua.BadSubscriptionIDInvalid
		}
	}
	ch.Write(
		&opcua.DeleteSubscriptionsResponse{
			ResponseHeader: opcua.ResponseHeader{
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
				&opcua.ServiceFault{
					ResponseHeader: opcua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHandle,
						ServiceResult: opcua.BadNoSubscription,
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
func (srv *Server) handlePublish(ch *serverSecureChannel, requestid uint32, req *opcua.PublishRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
	results := make([]opcua.StatusCode, len(req.SubscriptionAcknowledgements))
	for i, sa := range req.SubscriptionAcknowledgements {
		if sub, ok := sm.Get(sa.SubscriptionID); ok {
			if sub.acknowledge(sa.SequenceNumber) {
				results[i] = opcua.Good
			} else {
				results[i] = opcua.BadSequenceNumberUnknown
			}
		} else {
			results[i] = opcua.BadSubscriptionIDInvalid
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
			&opcua.PublishResponse{
				ResponseHeader: opcua.ResponseHeader{
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadNoSubscription,
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
func (srv *Server) handleRepublish(ch *serverSecureChannel, requestid uint32, req *opcua.RepublishRequest) error {
	// discovery only?
	if ch.discoveryOnly {
		ch.Abort(opcua.BadSecurityPolicyRejected, "")
		return nil
	}
	// get session
	session, ok := srv.SessionManager().Get(req.AuthenticationToken)
	if !ok {
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSessionNotActivated,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSecureChannelIDInvalid,
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
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHandle,
					ServiceResult: opcua.BadSubscriptionIDInvalid,
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
		if nm, ok := e.Value.(opcua.NotificationMessage); ok {
			if req.RetransmitSequenceNumber == nm.SequenceNumber {
				ch.Write(
					&opcua.RepublishResponse{
						ResponseHeader: opcua.ResponseHeader{
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
		&opcua.ServiceFault{
			ResponseHeader: opcua.ResponseHeader{
				Timestamp:     time.Now(),
				RequestHandle: req.RequestHandle,
				ServiceResult: opcua.BadMessageNotAvailable,
			},
		},
		requestid,
	)
	session.republishErrorCount++
	session.errorCount++
	return nil
}

// WriteValue writes the value of the attribute.
func (srv *Server) writeValue(ctx context.Context, writeValue opcua.WriteValue) opcua.StatusCode {
	n, ok := srv.NamespaceManager().FindNode(writeValue.NodeID)
	if !ok {
		return opcua.BadNodeIDUnknown
	}
	rp := n.UserRolePermissions(ctx)
	if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
		return opcua.BadNodeIDUnknown
	}
	switch writeValue.AttributeID {
	case opcua.AttributeIDValue:
		switch n1 := n.(type) {
		case *VariableNode:
			// if writeValue.Value.StatusCode != Good || !time.Time.IsZero(writeValue.Value.ServerTimestamp) || !time.Time.IsZero(writeValue.Value.SourceTimestamp) {
			// 	return opcua.BadWriteNotSupported
			// }
			if (n1.AccessLevel() & opcua.AccessLevelsCurrentWrite) == 0 {
				return opcua.BadNotWritable
			}
			if (n1.UserAccessLevel(ctx) & opcua.AccessLevelsCurrentWrite) == 0 {
				return opcua.BadUserAccessDenied
			}
			// check data type
			destType := srv.NamespaceManager().FindVariantType(n1.DataType())
			destRank := n1.ValueRank()
			// special case convert bytestring to byte array
			if destType == opcua.VariantTypeByte && destRank == opcua.ValueRankOneDimension {
				if v1, ok := writeValue.Value.Value.(opcua.ByteString); ok {
					writeValue.Value.Value = []byte(v1)
				}
			}
			// special case convert byte array to bytestring
			if destType == opcua.VariantTypeByteString && destRank == opcua.ValueRankScalar {
				if v1, ok := writeValue.Value.Value.([]byte); ok {
					writeValue.Value.Value = opcua.ByteString(v1)
				}
			}
			switch v2 := writeValue.Value.Value.(type) {
			case nil:
			case bool:
				if destType != opcua.VariantTypeBoolean && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case int8:
				if destType != opcua.VariantTypeSByte && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case uint8:
				if destType != opcua.VariantTypeByte && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case int16:
				if destType != opcua.VariantTypeInt16 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case uint16:
				if destType != opcua.VariantTypeUInt16 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case int32:
				if destType != opcua.VariantTypeInt32 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case uint32:
				if destType != opcua.VariantTypeUInt32 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case int64:
				if destType != opcua.VariantTypeInt64 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case uint64:
				if destType != opcua.VariantTypeUInt64 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case float32:
				if destType != opcua.VariantTypeFloat && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case float64:
				if destType != opcua.VariantTypeDouble && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case string:
				if len(v2) > int(srv.serverCapabilities.MaxStringLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeString && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case time.Time:
				if destType != opcua.VariantTypeDateTime && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case uuid.UUID:
				if destType != opcua.VariantTypeGUID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.ByteString:
				if len(v2) > int(srv.serverCapabilities.MaxByteStringLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeByteString && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.XMLElement:
				if destType != opcua.VariantTypeXMLElement && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.NodeID:
				if destType != opcua.VariantTypeNodeID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.ExpandedNodeID:
				if destType != opcua.VariantTypeExpandedNodeID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.StatusCode:
				if destType != opcua.VariantTypeStatusCode && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.QualifiedName:
				if destType != opcua.VariantTypeQualifiedName && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case opcua.LocalizedText:
				if destType != opcua.VariantTypeLocalizedText && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []bool:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeBoolean && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []int8:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeSByte && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []uint8:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeByte && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []int16:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeInt16 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []uint16:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeUInt16 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []int32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeInt32 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []uint32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeUInt32 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []int64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeInt64 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []uint64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeUInt64 && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []float32:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeFloat && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []float64:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeDouble && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []string:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeString && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []time.Time:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeDateTime && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []uuid.UUID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeGUID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.ByteString:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeByteString && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.XMLElement:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeXMLElement && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.NodeID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeNodeID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.ExpandedNodeID:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeExpandedNodeID && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.StatusCode:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeStatusCode && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.QualifiedName:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeQualifiedName && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.LocalizedText:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeLocalizedText && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.ExtensionObject:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeExtensionObject && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.DataValue:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeDataValue && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			case []opcua.Variant:
				if len(v2) > int(srv.serverCapabilities.MaxArrayLength) {
					return opcua.BadOutOfRange
				}
				if destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankOneDimension && destRank != opcua.ValueRankOneOrMoreDimensions && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			default:
			// case opcua.ExtensionObject:
				if destType != opcua.VariantTypeExtensionObject && destType != opcua.VariantTypeVariant {
					return opcua.BadTypeMismatch
				}
				if destRank != opcua.ValueRankScalar && destRank != opcua.ValueRankScalarOrOneDimension && destRank != opcua.ValueRankAny {
					return opcua.BadTypeMismatch
				}
			}

			if f := n1.writeValueHandler; f != nil {
				return f(ctx, writeValue)
			} else {
				result, status := writeRange(n1.Value(), writeValue.Value, writeValue.IndexRange)
				if status == opcua.Good {
					n1.SetValue(result)
				}
				return status
			}
		default:
			return opcua.BadAttributeIDInvalid
		}
	case opcua.AttributeIDHistorizing:
		switch n1 := n.(type) {
		case *VariableNode:
			// check for PermissionTypeWriteHistorizing
			if !IsUserPermitted(rp, opcua.PermissionTypeWriteHistorizing) {
				return opcua.BadUserAccessDenied
			}
			v, ok := writeValue.Value.Value.(bool)
			if !ok {
				return opcua.BadTypeMismatch
			}
			n1.SetHistorizing(v)
			return opcua.Good
		default:
			return opcua.BadAttributeIDInvalid
		}
	default:
		return opcua.BadAttributeIDInvalid
	}
}

// readValue returns the value of the attribute.
func (srv *Server) readValue(ctx context.Context, readValueId opcua.ReadValueID) opcua.DataValue {
	if readValueId.DataEncoding.Name != "" {
		return opcua.NewDataValue(nil, opcua.BadDataEncodingInvalid, time.Time{}, 0, time.Now(), 0)
	}
	if readValueId.IndexRange != "" && readValueId.AttributeID != opcua.AttributeIDValue {
		return opcua.NewDataValue(nil, opcua.BadIndexRangeNoData, time.Time{}, 0, time.Now(), 0)
	}
	n, ok := srv.NamespaceManager().FindNode(readValueId.NodeID)
	if !ok {
		return opcua.NewDataValue(nil, opcua.BadNodeIDUnknown, time.Time{}, 0, time.Now(), 0)
	}
	rp := n.UserRolePermissions(ctx)
	if !IsUserPermitted(rp, opcua.PermissionTypeBrowse) {
		return opcua.NewDataValue(nil, opcua.BadNodeIDUnknown, time.Time{}, 0, time.Now(), 0)
	}
	switch readValueId.AttributeID {
	case opcua.AttributeIDValue:
		switch n1 := n.(type) {
		case *VariableNode:
			// check the access level for the variable.
			if (n1.AccessLevel() & opcua.AccessLevelsCurrentRead) == 0 {
				return opcua.NewDataValue(nil, opcua.BadNotReadable, time.Time{}, 0, time.Now(), 0)
			}
			if (n1.UserAccessLevel(ctx) & opcua.AccessLevelsCurrentRead) == 0 {
				return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Time{}, 0, time.Now(), 0)
			}
			if f := n1.readValueHandler; f != nil {
				return f(ctx, readValueId)
			}
			return readRange(n1.Value(), readValueId.IndexRange)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDNodeID:
		return opcua.NewDataValue(n.NodeID(), opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDNodeClass:
		return opcua.NewDataValue(int32(n.NodeClass()), opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDBrowseName:
		return opcua.NewDataValue(n.BrowseName(), opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDDisplayName:
		return opcua.NewDataValue(n.DisplayName(), opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDDescription:
		return opcua.NewDataValue(n.Description(), opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDIsAbstract:
		switch n1 := n.(type) {
		case *DataTypeNode:
			return opcua.NewDataValue(n1.IsAbstract(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *ObjectTypeNode:
			return opcua.NewDataValue(n1.IsAbstract(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *ReferenceTypeNode:
			return opcua.NewDataValue(n1.IsAbstract(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return opcua.NewDataValue(n1.IsAbstract(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDSymmetric:
		switch n1 := n.(type) {
		case *ReferenceTypeNode:
			return opcua.NewDataValue(n1.Symmetric(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDInverseName:
		switch n1 := n.(type) {
		case *ReferenceTypeNode:
			return opcua.NewDataValue(n1.InverseName(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDContainsNoLoops:
		switch n1 := n.(type) {
		case *ViewNode:
			return opcua.NewDataValue(n1.ContainsNoLoops(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDEventNotifier:
		switch n1 := n.(type) {
		case *ObjectNode:
			return opcua.NewDataValue(n1.EventNotifier(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *ViewNode:
			return opcua.NewDataValue(n1.EventNotifier(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDDataType:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.DataType(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return opcua.NewDataValue(n1.DataType(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDValueRank:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.ValueRank(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return opcua.NewDataValue(n1.ValueRank(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDArrayDimensions:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.ArrayDimensions(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		case *VariableTypeNode:
			return opcua.NewDataValue(n1.ArrayDimensions(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDAccessLevel:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.AccessLevel(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDUserAccessLevel:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.UserAccessLevel(ctx), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDMinimumSamplingInterval:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.MinimumSamplingInterval(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDHistorizing:
		switch n1 := n.(type) {
		case *VariableNode:
			return opcua.NewDataValue(n1.Historizing(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDExecutable:
		switch n1 := n.(type) {
		case *MethodNode:
			return opcua.NewDataValue(n1.Executable(), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDUserExecutable:
		switch n1 := n.(type) {
		case *MethodNode:
			return opcua.NewDataValue(n1.UserExecutable(ctx), opcua.Good, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDDataTypeDefinition:
		switch n1 := n.(type) {
		case *DataTypeNode:
			if def := n1.DataTypeDefinition(); def != nil {
				return opcua.NewDataValue(def, opcua.Good, time.Time{}, 0, time.Now(), 0)
			}
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		default:
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
	case opcua.AttributeIDRolePermissions:
		if !IsUserPermitted(rp, opcua.PermissionTypeReadRolePermissions) {
			return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
		}
		s1 := n.RolePermissions()
		s2 := make([]opcua.ExtensionObject, len(s1))
		for i := range s1 {
			s2[i] = s1[i]
		}
		return opcua.NewDataValue(s2, opcua.Good, time.Time{}, 0, time.Now(), 0)
	case opcua.AttributeIDUserRolePermissions:
		s1 := n.UserRolePermissions(ctx)
		s2 := make([]opcua.ExtensionObject, len(s1))
		for i := range s1 {
			s2[i] = s1[i]
		}
		return opcua.NewDataValue(s2, opcua.Good, time.Time{}, 0, time.Now(), 0)
	default:
		return opcua.NewDataValue(nil, opcua.BadAttributeIDInvalid, time.Time{}, 0, time.Now(), 0)
	}
}
