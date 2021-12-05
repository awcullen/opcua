// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math"
	"net"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/awcullen/opcua"

	"github.com/djherbis/buffer"
)

const (
	// defaultTimeoutHint is the default number of milliseconds before a request is cancelled. (15 sec)
	defaultTimeoutHint uint32 = 15000
	// defaultDiagnosticsHint is the default diagnostic hint that is sent in a request. (None)
	defaultDiagnosticsHint uint32 = 0x00000000
	// defaultTokenRequestedLifetime is the number of milliseconds before a security token is expired. (60 min)
	defaultTokenRequestedLifetime uint32 = 3600000
	// defaultConnectTimeout sets the number of milliseconds to wait for a connection response.
	defaultConnectTimeout int64 = 5000
	// the default number of milliseconds that a session may be unused before being closed by the server. (2 min)
	defaultSessionTimeout float64 = 120 * 1000
	// documents the version of binary protocol that this library supports.
	protocolVersion uint32 = 0
	// the default size of the send and recieve buffers.
	defaultBufferSize uint32 = 64 * 1024
	// the limit on the size of messages that may be accepted.
	defaultMaxMessageSize uint32 = 16 * 1024 * 1024
	// defaultMaxChunkCount sets the limit on the number of message chunks that may be accepted.
	defaultMaxChunkCount uint32 = 4 * 1024
	// sequenceHeaderSize is the size of the sequence header
	sequenceHeaderSize int = 8
	// the length of nonce in bytes.
	nonceLength int = 32
)

// clientSecureChannel implements a secure channel for binary data over Tcp.
type clientSecureChannel struct {
	sync.RWMutex
	localDescription                   opcua.ApplicationDescription
	applicationCertificate             tls.Certificate
	timeoutHint                        uint32
	diagnosticsHint                    uint32
	tokenRequestedLifetime             uint32
	endpointURL                        string
	receiveBufferSize                  uint32
	sendBufferSize                     uint32
	maxMessageSize                     uint32
	maxChunkCount                      uint32
	conn                               net.Conn
	connectTimeout                     int64
	trustedCertsFile                   string
	suppressHostNameInvalid            bool
	suppressCertificateExpired         bool
	suppressCertificateChainIncomplete bool
	//
	localCertificate           []byte
	remoteCertificate          []byte
	localPrivateKey            *rsa.PrivateKey
	remotePublicKey            *rsa.PublicKey
	localNonce                 []byte
	remoteNonce                []byte
	channelID                  uint32
	tokenID                    uint32
	tokenLock                  sync.RWMutex
	authenticationToken        opcua.NodeID
	securityPolicyURI          string
	securityPolicy             opcua.SecurityPolicy
	securityMode               opcua.MessageSecurityMode
	namespaceURIs              []string
	serverURIs                 []string
	cancellation               chan struct{}
	errCode                    opcua.StatusCode
	sendingSemaphore           sync.Mutex
	receivingSemaphore         sync.Mutex
	pendingResponseCh          chan *opcua.ServiceOperation
	pendingResponses           map[uint32]*opcua.ServiceOperation
	reconnecting               bool
	closing                    bool
	requestHandleLock          sync.Mutex
	requestHandle              uint32
	sequenceNumberLock         sync.Mutex
	sequenceNumber             uint32
	sendingTokenID             uint32
	receivingTokenID           uint32
	localSigningKey            []byte
	localEncryptingKey         []byte
	localInitializationVector  []byte
	remoteSigningKey           []byte
	remoteEncryptingKey        []byte
	remoteInitializationVector []byte
	tokenRenewalTime           time.Time
	symSignHMAC                hash.Hash
	symVerifyHMAC              hash.Hash
	symSign                    func(mac hash.Hash, plainText []byte) ([]byte, error)
	symVerify                  func(mac hash.Hash, plainText, signature []byte) error
	symEncryptingBlockCipher   cipher.Block
	symDecryptingBlockCipher   cipher.Block
	trace                      bool
}

// newClientSecureChannel initializes a new instance of the secure channel.
func newClientSecureChannel(
	localDescription opcua.ApplicationDescription,
	localCertificate []byte,
	localPrivateKey *rsa.PrivateKey,
	endpointURL string,
	securityPolicyURI string,
	securityMode opcua.MessageSecurityMode,
	remoteCertificate []byte,
	connectTimeout int64,
	applicationCertificate tls.Certificate,
	trustedCertsFile string,
	suppressHostNameInvalid bool,
	suppressCertificateExpired bool,
	suppressCertificateChainIncomplete bool,
	timeoutHint uint32,
	diagnosticsHint uint32,
	tokenLifetime uint32,
	trace bool,
) *clientSecureChannel {

	ch := &clientSecureChannel{
		localDescription:                   localDescription,
		endpointURL:                        endpointURL,
		securityPolicyURI:                  securityPolicyURI,
		securityMode:                       securityMode,
		localCertificate:                   localCertificate,
		localPrivateKey:                    localPrivateKey,
		remoteCertificate:                  remoteCertificate,
		namespaceURIs:                      []string{"http://opcfoundation.org/UA/"},
		serverURIs:                         []string{},
		connectTimeout:                     connectTimeout,
		applicationCertificate:             applicationCertificate,
		trustedCertsFile:                   trustedCertsFile,
		suppressHostNameInvalid:            suppressHostNameInvalid,
		suppressCertificateExpired:         suppressCertificateExpired,
		suppressCertificateChainIncomplete: suppressCertificateChainIncomplete,
		timeoutHint:                        timeoutHint,
		diagnosticsHint:                    diagnosticsHint,
		tokenRequestedLifetime:             tokenLifetime,
		trace:                              trace,
	}
	if cert, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
		ch.remotePublicKey = cert.PublicKey.(*rsa.PublicKey)
	}
	return ch
}

// EndpointURL gets the URL of the remote endpoint.
func (ch *clientSecureChannel) EndpointURL() string {
	return ch.endpointURL
}

// ReceiveBufferSize gets the size of the local receive buffer.
func (ch *clientSecureChannel) ReceiveBufferSize() uint32 {
	return ch.receiveBufferSize
}

// SendBufferSize gets the size of the local send buffer.
func (ch *clientSecureChannel) SendBufferSize() uint32 {
	return ch.sendBufferSize
}

// MaxMessageSize gets the maximum size of message that may be sent to the remote endpoint.
func (ch *clientSecureChannel) MaxMessageSize() uint32 {
	return ch.maxMessageSize
}

// MaxChunkCount gets the maximum number of chunks that may be sent to the remote endpoint.
func (ch *clientSecureChannel) MaxChunkCount() uint32 {
	return ch.maxChunkCount
}

// SetAuthenticationToken sets the authentication token.
func (ch *clientSecureChannel) SetAuthenticationToken(value opcua.NodeID) {
	ch.Lock()
	defer ch.Unlock()
	ch.authenticationToken = value
}

// NamespaceURIs gets the namespace uris.
func (ch *clientSecureChannel) NamespaceURIs() []string {
	ch.RLock()
	defer ch.RUnlock()
	return ch.namespaceURIs
}

// SetNamespaceURIs sets the namespace uris.
func (ch *clientSecureChannel) SetNamespaceURIs(value []string) {
	ch.Lock()
	defer ch.Unlock()
	ch.namespaceURIs = value
}

// ServerURIs gets the server uris.
func (ch *clientSecureChannel) ServerURIs() []string {
	ch.RLock()
	defer ch.RUnlock()
	return ch.serverURIs
}

// SetServerURIs sets the server uris.
func (ch *clientSecureChannel) SetServerURIs(value []string) {
	ch.Lock()
	defer ch.Unlock()
	ch.serverURIs = value
}

// Request sends a service request to the server and returns the response.
func (ch *clientSecureChannel) Request(ctx context.Context, req opcua.ServiceRequest) (opcua.ServiceResponse, error) {
	header := req.Header()
	header.Timestamp = time.Now()
	header.RequestHandle = ch.getNextRequestHandle()
	header.AuthenticationToken = ch.authenticationToken
	if header.TimeoutHint == 0 {
		header.TimeoutHint = defaultTimeoutHint
	}
	var operation = opcua.NewServiceOperation(req, make(chan opcua.ServiceResponse, 1))
	ch.pendingResponseCh <- operation
	ctx, cancel := context.WithDeadline(ctx, header.Timestamp.Add(time.Duration(header.TimeoutHint)*time.Millisecond))
	err := ch.sendRequest(ctx, operation)
	if err != nil {
		cancel()
		return nil, err
	}
	select {
	case res := <-operation.ResponseCh():
		if sr := res.Header().ServiceResult; sr != opcua.Good {
			cancel()
			return nil, sr
		}
		cancel()
		return res, nil
	case <-ctx.Done():
		cancel()
		return nil, opcua.BadRequestTimeout
	case <-ch.cancellation:
		cancel()
		return nil, ch.errCode
	}
}

// Open opens the channel.
func (ch *clientSecureChannel) Open(ctx context.Context) error {
	ch.Lock()
	defer ch.Unlock()

	remoteURL, err := url.Parse(ch.endpointURL)
	if err != nil {
		return err
	}

	if len(ch.remoteCertificate) > 0 {
		cert, err := x509.ParseCertificate(ch.remoteCertificate)
		if err != nil {
			return opcua.BadSecurityChecksFailed
		}
		_, err = validateServerCertificate(cert, remoteURL.Hostname(), ch.trustedCertsFile, ch.suppressHostNameInvalid, ch.suppressCertificateExpired, ch.suppressCertificateChainIncomplete)
		if err != nil {
			return err
		}
	}

	ch.conn, err = net.DialTimeout("tcp", remoteURL.Host, time.Duration(ch.connectTimeout)*time.Millisecond)
	if err != nil {
		return err
	}

	buf := *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&buf)
	var writer = opcua.NewWriter(buf)
	var enc = opcua.NewBinaryEncoder(writer, ch)
	enc.WriteUInt32(opcua.MessageTypeHello)
	enc.WriteUInt32(uint32(32 + len(ch.endpointURL)))
	enc.WriteUInt32(protocolVersion)
	enc.WriteUInt32(defaultBufferSize)
	enc.WriteUInt32(defaultBufferSize)
	enc.WriteUInt32(defaultMaxMessageSize)
	enc.WriteUInt32(defaultMaxChunkCount)
	enc.WriteString(ch.endpointURL)
	_, err = ch.Write(writer.Bytes())
	if err != nil {
		return err
	}

	if ch.trace {
		log.Printf("Hello{\"Version\":%d,\"ReceiveBufferSize\":%d,\"SendBufferSize\":%d,\"MaxMessageSize\":%d,\"MaxChunkCount\":%d,\"EndpointURL\":\"%s\"}\n", protocolVersion, defaultBufferSize, defaultBufferSize, defaultMaxMessageSize, defaultMaxChunkCount, ch.endpointURL)
	}

	_, err = ch.Read(buf)
	if err != nil {
		return err
	}

	var reader = bytes.NewReader(buf)
	var dec = opcua.NewBinaryDecoder(reader, ch)
	var msgType uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return err
	}
	var msgLen uint32
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return err
	}

	switch msgType {
	case opcua.MessageTypeAck:
		if msgLen < 28 {
			return opcua.BadDecodingError
		}
		var remoteProtocolVersion uint32
		if err := dec.ReadUInt32(&remoteProtocolVersion); err != nil {
			return err
		}
		if remoteProtocolVersion < protocolVersion {
			return opcua.BadProtocolVersionUnsupported
		}
		if err := dec.ReadUInt32(&ch.sendBufferSize); err != nil {
			return err
		}
		if err := dec.ReadUInt32(&ch.receiveBufferSize); err != nil {
			return err
		}
		if err := dec.ReadUInt32(&ch.maxMessageSize); err != nil {
			return err
		}
		if err := dec.ReadUInt32(&ch.maxChunkCount); err != nil {
			return err
		}
		if ch.trace {
			log.Printf("Ack{\"Version\":%d,\"ReceiveBufferSize\":%d,\"SendBufferSize\":%d,\"MaxMessageSize\":%d,\"MaxChunkCount\":%d}\n", remoteProtocolVersion, ch.sendBufferSize, ch.receiveBufferSize, ch.maxMessageSize, ch.maxChunkCount)
		}

	case opcua.MessageTypeError:
		if msgLen < 16 {
			return opcua.BadDecodingError
		}
		var remoteCode uint32
		if err := dec.ReadUInt32(&remoteCode); err != nil {
			return err
		}
		var unused string
		if err = dec.ReadString(&unused); err != nil {
			return err
		}
		return opcua.StatusCode(remoteCode)

	default:
		return opcua.BadDecodingError
	}

	switch ch.securityMode {
	case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:

		if ch.localPrivateKey == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.remotePublicKey == nil {
			return opcua.BadSecurityChecksFailed
		}

		switch ch.securityPolicyURI {
		case opcua.SecurityPolicyURIBasic128Rsa15:
			ch.securityPolicy = new(opcua.SecurityPolicyBasic128Rsa15)

		case opcua.SecurityPolicyURIBasic256:
			ch.securityPolicy = new(opcua.SecurityPolicyBasic256)

		case opcua.SecurityPolicyURIBasic256Sha256:
			ch.securityPolicy = new(opcua.SecurityPolicyBasic256Sha256)

		case opcua.SecurityPolicyURIAes128Sha256RsaOaep:
			ch.securityPolicy = new(opcua.SecurityPolicyAes128Sha256RsaOaep)

		case opcua.SecurityPolicyURIAes256Sha256RsaPss:
			ch.securityPolicy = new(opcua.SecurityPolicyAes256Sha256RsaPss)

		default:
			return opcua.BadSecurityPolicyRejected
		}

		ch.localSigningKey = make([]byte, ch.securityPolicy.SymSignatureKeySize())
		ch.localEncryptingKey = make([]byte, ch.securityPolicy.SymEncryptionKeySize())
		ch.localInitializationVector = make([]byte, ch.securityPolicy.SymEncryptionBlockSize())
		ch.remoteSigningKey = make([]byte, ch.securityPolicy.SymSignatureKeySize())
		ch.remoteEncryptingKey = make([]byte, ch.securityPolicy.SymEncryptionKeySize())
		ch.remoteInitializationVector = make([]byte, ch.securityPolicy.SymEncryptionBlockSize())
		ch.symSign = func(mac hash.Hash, plainText []byte) ([]byte, error) {
			mac.Reset()
			mac.Write(plainText)
			return mac.Sum(nil), nil
		}
		ch.symVerify = func(mac hash.Hash, plainText, signature []byte) error {
			mac.Reset()
			mac.Write(plainText)
			sig := mac.Sum(nil)
			if !hmac.Equal(sig, signature) {
				return opcua.BadSecurityChecksFailed
			}
			return nil
		}

	default:
		ch.securityPolicy = new(opcua.SecurityPolicyNone)

	}

	ch.pendingResponseCh = make(chan *opcua.ServiceOperation, 32)
	ch.pendingResponses = make(map[uint32]*opcua.ServiceOperation)
	ch.cancellation = make(chan struct{})
	ch.channelID = 0
	ch.tokenID = 0
	ch.sendingTokenID = 0
	ch.receivingTokenID = 0

	go ch.responseWorker()

	request := &opcua.OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           opcua.SecurityTokenRequestTypeIssue,
		SecurityMode:          ch.securityMode,
		ClientNonce:           opcua.ByteString(getNextNonce(ch.securityPolicy.NonceSize())),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*opcua.OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return opcua.BadProtocolVersionUnsupported
	}

	ch.tokenLock.Lock()
	ch.tokenRenewalTime = time.Now().Add(time.Duration(response.SecurityToken.RevisedLifetime*75/100) * time.Millisecond)
	ch.channelID = response.SecurityToken.ChannelID
	ch.tokenID = response.SecurityToken.TokenID
	ch.localNonce = []byte(request.ClientNonce)
	ch.remoteNonce = []byte(response.ServerNonce)
	ch.tokenLock.Unlock()
	return nil
}

// Close closes the channel.
func (ch *clientSecureChannel) Close(ctx context.Context) error {
	ch.Lock()
	defer ch.Unlock()
	ch.closing = true
	var request = &opcua.CloseSecureChannelRequest{}
	_, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	if ch.conn != nil {
		return ch.conn.Close()
	}
	return nil
}

// Abort closes the channel abruptly.
func (ch *clientSecureChannel) Abort(ctx context.Context) error {
	ch.Lock()
	defer ch.Unlock()
	if ch.conn != nil {
		return ch.conn.Close()
	}
	return nil
}

// sendRequest sends the service request on transport channel.
func (ch *clientSecureChannel) sendRequest(ctx context.Context, op *opcua.ServiceOperation) error {
	// Check if time to renew security token.
	if !ch.tokenRenewalTime.IsZero() && time.Now().After(ch.tokenRenewalTime) {
		ch.tokenRenewalTime = ch.tokenRenewalTime.Add(60000 * time.Millisecond)
		ch.renewToken(ctx)
	}

	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()

	req := op.Request()

	if ch.trace {
		b, _ := json.MarshalIndent(req, "", " ")
		log.Printf("%s%s", reflect.TypeOf(req).Elem().Name(), b)
	}

	switch req := req.(type) {
	case *opcua.OpenSecureChannelRequest:
		err := ch.sendOpenSecureChannelRequest(ctx, req)
		if err != nil {
			return err
		}
	case *opcua.CloseSecureChannelRequest:
		err := ch.sendServiceRequest(ctx, req)
		if err != nil {
			return err
		}
		// send a success response to ourselves (the server will just close it's socket).
		select {
		case op.ResponseCh() <- &opcua.CloseSecureChannelResponse{ResponseHeader: opcua.ResponseHeader{RequestHandle: req.RequestHandle, Timestamp: time.Now()}}:
		default:
		}
	default:
		err := ch.sendServiceRequest(ctx, req)
		if err != nil {
			return err
		}
	}
	return nil
}

// sendOpenSecureChannelRequest sends open secure channel service request on transport channel.
func (ch *clientSecureChannel) sendOpenSecureChannelRequest(ctx context.Context, request *opcua.OpenSecureChannelRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&sendBuffer)

	var bodyEncoder = opcua.NewBinaryEncoder(bodyStream, ch)

	if err := bodyEncoder.WriteNodeID(opcua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary); err != nil {
		return opcua.BadEncodingError
	}

	if err := bodyEncoder.Encode(request); err != nil {
		return opcua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return opcua.BadEncodingLimitsExceeded
	}

	// write chunks
	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return opcua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var signatureSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		var cipherTextBlockSize int
		var plainTextBlockSize int
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			plainHeaderSize = 16 + len(ch.securityPolicyURI) + 28 + len(ch.localCertificate)
			signatureSize = ch.localPrivateKey.Size()
			cipherTextBlockSize = ch.remotePublicKey.Size()
			plainTextBlockSize = cipherTextBlockSize - ch.securityPolicy.RSAPaddingSize()
			if cipherTextBlockSize > 256 {
				paddingHeaderSize = 2
			} else {
				paddingHeaderSize = 1
			}
			maxBodySize = (((int(ch.sendBufferSize) - plainHeaderSize) / cipherTextBlockSize) * plainTextBlockSize) - sequenceHeaderSize - paddingHeaderSize - signatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
				paddingSize = (plainTextBlockSize - ((sequenceHeaderSize + bodySize + paddingHeaderSize + signatureSize) % plainTextBlockSize)) % plainTextBlockSize
			} else {
				bodySize = maxBodySize
				paddingSize = 0
			}
			chunkSize = plainHeaderSize + (((sequenceHeaderSize + bodySize + paddingSize + paddingHeaderSize + signatureSize) / plainTextBlockSize) * cipherTextBlockSize)

		default:
			plainHeaderSize = int(16 + len(ch.securityPolicyURI) + 8)
			signatureSize = 0
			paddingHeaderSize = 0
			paddingSize = 0
			cipherTextBlockSize = 1
			plainTextBlockSize = 1
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize
		}

		var stream = opcua.NewWriter(sendBuffer)
		var encoder = opcua.NewBinaryEncoder(stream, ch)

		// header
		encoder.WriteUInt32(opcua.MessageTypeOpenFinal)
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// asymmetric security header
		encoder.WriteString(ch.securityPolicyURI)
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			encoder.WriteByteArray(ch.localCertificate)
			thumbprint := sha1.Sum(ch.remoteCertificate)
			encoder.WriteByteArray(thumbprint[:])
		default:
			encoder.WriteByteArray(nil)
			encoder.WriteByteArray(nil)
		}

		if plainHeaderSize != int(stream.Len()) {
			return opcua.BadEncodingError
		}

		// sequence header
		encoder.WriteUInt32(ch.getNextSequenceNumber())
		encoder.WriteUInt32(request.RequestHandle)

		// body
		_, err := io.CopyN(stream, bodyStream, int64(bodySize))
		if err != nil {
			return err
		}
		bodyCount -= bodySize

		// padding
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			paddingByte := byte(paddingSize & 0xFF)
			encoder.WriteByte(paddingByte)
			for i := int(0); i < paddingSize; i++ {
				encoder.WriteByte(paddingByte)
			}

			if paddingHeaderSize == 2 {
				extraPaddingByte := byte((paddingSize >> 8) & 0xFF)
				encoder.WriteByte(extraPaddingByte)
			}
		}

		if bodyCount > 0 {
			return opcua.BadEncodingError
		}

		// sign
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			signature, err := ch.securityPolicy.RSASign(ch.localPrivateKey, stream.Bytes())
			if err != nil {
				return err
			}
			if len(signature) != signatureSize {
				return opcua.BadEncodingError
			}
			_, err = stream.Write(signature)
			if err != nil {
				return err
			}
		}

		// encrypt
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			var encryptionBuffer = *(bytesPool.Get().(*[]byte))
			defer bytesPool.Put(&encryptionBuffer)

			position := int(stream.Len())
			copy(encryptionBuffer, stream.Bytes()[:plainHeaderSize])
			plainText := make([]byte, plainTextBlockSize)
			jj := plainHeaderSize
			for ii := plainHeaderSize; ii < position; ii += plainTextBlockSize {
				copy(plainText, stream.Bytes()[ii:])
				// encrypt with remote public key.
				cipherText, err := ch.securityPolicy.RSAEncrypt(ch.remotePublicKey, plainText)
				if err != nil {
					return err
				}
				if len(cipherText) != cipherTextBlockSize {
					return opcua.BadEncodingError
				}
				copy(encryptionBuffer[jj:], cipherText)
				jj += cipherTextBlockSize
			}
			if jj != chunkSize {
				return opcua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.Write(encryptionBuffer[:chunkSize])
			if err != nil {
				return err
			}

		default:

			if stream.Len() != chunkSize {
				return opcua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.Write(stream.Bytes())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// sendServiceRequest sends the service request on transport channel.
func (ch *clientSecureChannel) sendServiceRequest(ctx context.Context, request opcua.ServiceRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&sendBuffer)

	var bodyEncoder = opcua.NewBinaryEncoder(bodyStream, ch)

	switch req := request.(type) {

	// frequent
	case *opcua.PublishRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDPublishRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ReadRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDReadRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.BrowseRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDBrowseRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.BrowseNextRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDBrowseNextRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.TranslateBrowsePathsToNodeIDsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDTranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.WriteRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDWriteRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CallRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCallRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.HistoryReadRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDHistoryReadRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}

	// moderate
	case *opcua.GetEndpointsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDGetEndpointsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.OpenSecureChannelRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CloseSecureChannelRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCloseSecureChannelRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateSessionRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateSessionRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ActivateSessionRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDActivateSessionRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CloseSessionRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCloseSessionRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateSubscriptionRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateSubscriptionRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteSubscriptionsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteSubscriptionsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetPublishingModeRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetPublishingModeRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}

		// rare
	case *opcua.ModifyMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDModifyMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetMonitoringModeRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetMonitoringModeRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetTriggeringRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetTriggeringRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ModifySubscriptionRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDModifySubscriptionRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RepublishRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRepublishRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.TransferSubscriptionsRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDTransferSubscriptionsRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.FindServersRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDFindServersRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.FindServersOnNetworkRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDFindServersOnNetworkRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterServerRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterServerRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterServer2Request:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterServer2RequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CancelRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCancelRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.AddNodesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDAddNodesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.AddReferencesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDAddReferencesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteNodesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteNodesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteReferencesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteReferencesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterNodesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterNodesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.UnregisterNodesRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDUnregisterNodesRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.QueryFirstRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDQueryFirstRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.QueryNextRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDQueryNextRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.HistoryUpdateRequest:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDHistoryUpdateRequestEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return opcua.BadEncodingError
		}
	default:
		return opcua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return opcua.BadEncodingLimitsExceeded
	}

	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return opcua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt:
			plainHeaderSize = 16
			if ch.securityPolicy.SymEncryptionBlockSize() > 256 {
				paddingHeaderSize = 2
			} else {
				paddingHeaderSize = 1
			}
			maxBodySize = (((int(ch.sendBufferSize) - plainHeaderSize) / ch.securityPolicy.SymEncryptionBlockSize()) * ch.securityPolicy.SymEncryptionBlockSize()) - sequenceHeaderSize - paddingHeaderSize - ch.securityPolicy.SymSignatureSize()
			if bodyCount < maxBodySize {
				bodySize = bodyCount
				paddingSize = (ch.securityPolicy.SymEncryptionBlockSize() - ((sequenceHeaderSize + bodySize + paddingHeaderSize + ch.securityPolicy.SymSignatureSize()) % ch.securityPolicy.SymEncryptionBlockSize())) % ch.securityPolicy.SymEncryptionBlockSize()
			} else {
				bodySize = maxBodySize
				paddingSize = 0
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + paddingSize + paddingHeaderSize + ch.securityPolicy.SymSignatureSize()

		default:
			plainHeaderSize = 16
			paddingHeaderSize = 0
			paddingSize = 0
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize - ch.securityPolicy.SymSignatureSize()
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + ch.securityPolicy.SymSignatureSize()
		}

		var stream = opcua.NewWriter(sendBuffer)
		var encoder = opcua.NewBinaryEncoder(stream, ch)

		// header
		if bodyCount > bodySize {
			encoder.WriteUInt32(opcua.MessageTypeChunk)
		} else {
			encoder.WriteUInt32(opcua.MessageTypeFinal)
		}
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// symmetric security header
		encoder.WriteUInt32(ch.tokenID)

		// detect new TokenId
		ch.tokenLock.RLock()
		if ch.tokenID != ch.sendingTokenID {
			ch.sendingTokenID = ch.tokenID

			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
				// (re)create local security keys for encrypting the next message sent
				localSecurityKey := calculatePSHA(ch.remoteNonce, ch.localNonce, len(ch.localSigningKey)+len(ch.localEncryptingKey)+len(ch.localInitializationVector), ch.securityPolicyURI)
				jj := copy(ch.localSigningKey, localSecurityKey)
				jj += copy(ch.localEncryptingKey, localSecurityKey[jj:])
				copy(ch.localInitializationVector, localSecurityKey[jj:])
				// update signer and encrypter with new symmetric keys
				ch.symSignHMAC = ch.securityPolicy.SymHMACFactory(ch.localSigningKey)
				if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
					ch.symEncryptingBlockCipher, _ = aes.NewCipher(ch.localEncryptingKey)
				}
			}
		}
		ch.tokenLock.RUnlock()

		// sequence header
		encoder.WriteUInt32(ch.getNextSequenceNumber())
		encoder.WriteUInt32(request.Header().RequestHandle)

		// body
		_, err := io.CopyN(stream, bodyStream, int64(bodySize))
		if err != nil {
			return err
		}
		bodyCount -= bodySize

		// padding
		if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
			paddingByte := byte(paddingSize & 0xFF)
			encoder.WriteByte(paddingByte)
			for i := 0; i < paddingSize; i++ {
				encoder.WriteByte(paddingByte)
			}

			if paddingHeaderSize == 2 {
				extraPaddingByte := byte((paddingSize >> 8) & 0xFF)
				encoder.WriteByte(extraPaddingByte)
			}
		}

		// sign
		switch ch.securityMode {
		case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
			signature, err := ch.symSign(ch.symSignHMAC, stream.Bytes())
			if err != nil {
				return err
			}
			stream.Write(signature)
		}

		// encrypt
		if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
			span := stream.Bytes()[plainHeaderSize:]
			if len(span)%ch.symEncryptingBlockCipher.BlockSize() != 0 {
				return opcua.BadEncodingError
			}
			cipher.NewCBCEncrypter(ch.symEncryptingBlockCipher, ch.localInitializationVector).CryptBlocks(span, span)
		}

		// pass buffer to transport
		_, err = ch.Write(stream.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

// responseWorker starts a task to receive service responses from transport channel.
func (ch *clientSecureChannel) responseWorker() {
	for {
		res, err := ch.readResponse()
		if err != nil {
			if ch.reconnecting {
				time.Sleep(1000 * time.Millisecond)
				continue
			}
			if ch.errCode == opcua.Good {
				if ec, ok := err.(opcua.StatusCode); ok {
					ch.errCode = ec
				}
			}
			close(ch.cancellation)
			return
		}
		ch.handleResponse(res)
	}
}

// readResponse receives next service response from transport channel.
func (ch *clientSecureChannel) readResponse() (opcua.ServiceResponse, error) {
	ch.receivingSemaphore.Lock()
	defer ch.receivingSemaphore.Unlock()
	var res opcua.ServiceResponse
	var paddingHeaderSize int
	var plainHeaderSize int
	var bodySize int
	var paddingSize int

	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var receiveBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&receiveBuffer)

	var bodyDecoder = opcua.NewBinaryDecoder(bodyStream, ch)

	// read chunks
	var chunkCount int32
	var isFinal bool

	for !isFinal {
		chunkCount++
		if i := int32(ch.maxChunkCount); i > 0 && chunkCount > i {
			return nil, opcua.BadEncodingLimitsExceeded
		}

		count, err := ch.Read(receiveBuffer)
		if err != nil || count == 0 {
			return nil, opcua.BadSecureChannelClosed
		}

		var stream = bytes.NewReader(receiveBuffer[0:count])
		var decoder = opcua.NewBinaryDecoder(stream, ch)

		var messageType uint32
		if err := decoder.ReadUInt32(&messageType); err != nil {
			return nil, opcua.BadDecodingError
		}
		var messageLength uint32
		if err := decoder.ReadUInt32(&messageLength); err != nil {
			return nil, opcua.BadDecodingError
		}

		if count != int(messageLength) {
			return nil, opcua.BadDecodingError
		}

		switch messageType {
		case opcua.MessageTypeChunk, opcua.MessageTypeFinal:
			// header
			var channelID uint32
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, opcua.BadDecodingError
			}
			if channelID != ch.channelID {
				return nil, opcua.BadTCPSecureChannelUnknown
			}

			// symmetric security header
			var tokenID uint32
			if err := decoder.ReadUInt32(&tokenID); err != nil {
				return nil, opcua.BadDecodingError
			}

			// detect new token
			ch.tokenLock.RLock()
			if tokenID != ch.receivingTokenID {
				ch.receivingTokenID = tokenID

				switch ch.securityMode {
				case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
					// (re)create remote security keys for decrypting the next message received that has a new TokenId
					remoteSecurityKey := calculatePSHA(ch.localNonce, ch.remoteNonce, len(ch.remoteSigningKey)+len(ch.remoteEncryptingKey)+len(ch.remoteInitializationVector), ch.securityPolicyURI)
					jj := copy(ch.remoteSigningKey, remoteSecurityKey)
					jj += copy(ch.remoteEncryptingKey, remoteSecurityKey[jj:])
					copy(ch.remoteInitializationVector, remoteSecurityKey[jj:])
					// update verifier and decrypter with new symmetric keys
					ch.symVerifyHMAC = ch.securityPolicy.SymHMACFactory(ch.remoteSigningKey)
					if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
						ch.symDecryptingBlockCipher, _ = aes.NewCipher(ch.remoteEncryptingKey)
					}
				}
			}
			ch.tokenLock.RUnlock()

			plainHeaderSize = 16
			// decrypt
			if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
				span := receiveBuffer[plainHeaderSize:count]
				if len(span)%ch.symDecryptingBlockCipher.BlockSize() != 0 {
					return nil, opcua.BadDecodingError
				}
				cipher.NewCBCDecrypter(ch.symDecryptingBlockCipher, ch.remoteInitializationVector).CryptBlocks(span, span)
			}

			// verify
			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
				sigStart := count - ch.securityPolicy.SymSignatureSize()
				err := ch.symVerify(ch.symVerifyHMAC, receiveBuffer[:sigStart], receiveBuffer[sigStart:count])
				if err != nil {
					return nil, err
				}
			}

			// read sequence header
			var unused uint32
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, opcua.BadDecodingError
			}

			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, opcua.BadDecodingError
			}

			// body
			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt:
				if ch.securityPolicy.SymEncryptionBlockSize() > 256 {
					paddingHeaderSize = 2
					start := int(messageLength) - ch.securityPolicy.SymSignatureSize() - paddingHeaderSize
					paddingSize = int(binary.LittleEndian.Uint16(receiveBuffer[start : start+2]))
				} else {
					paddingHeaderSize = 1
					start := int(messageLength) - ch.securityPolicy.SymSignatureSize() - paddingHeaderSize
					paddingSize = int(receiveBuffer[start])
				}
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - paddingSize - paddingHeaderSize - ch.securityPolicy.SymSignatureSize()

			default:
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - ch.securityPolicy.SymSignatureSize()
			}

			m := plainHeaderSize + sequenceHeaderSize
			n := m + bodySize
			_, err = bodyStream.Write(receiveBuffer[m:n])
			if err != nil {
				return nil, err
			}

			isFinal = messageType == opcua.MessageTypeFinal

		case opcua.MessageTypeOpenFinal:
			// header
			var unused1 uint32
			if err = decoder.ReadUInt32(&unused1); err != nil {
				return nil, opcua.BadDecodingError
			}
			// asymmetric header
			var unused2 string
			if err = decoder.ReadString(&unused2); err != nil {
				return nil, opcua.BadDecodingError
			}
			var unused3 opcua.ByteString
			if err := decoder.ReadByteString(&unused3); err != nil {
				return nil, opcua.BadDecodingError
			}
			if err := decoder.ReadByteString(&unused3); err != nil {
				return nil, opcua.BadDecodingError
			}
			plainHeaderSize = count - stream.Len()

			// decrypt
			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
				cipherTextBlockSize := ch.localPrivateKey.Size()
				cipherText := make([]byte, cipherTextBlockSize)
				jj := plainHeaderSize
				for ii := plainHeaderSize; ii < int(messageLength); ii += cipherTextBlockSize {
					copy(cipherText, receiveBuffer[ii:])
					// decrypt with local private key.
					plainText, err := ch.securityPolicy.RSADecrypt(ch.localPrivateKey, cipherText)
					if err != nil {
						return nil, err
					}
					jj += copy(receiveBuffer[jj:], plainText)
				}
				// msg is shorter after decryption
				messageLength = uint32(jj)
			}

			// verify
			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
				// verify with remote public key.
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.remotePublicKey.Size()
				err := ch.securityPolicy.RSAVerify(ch.remotePublicKey, receiveBuffer[:sigStart], receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, opcua.BadDecodingError
				}
			}

			// sequence header
			var unused uint32
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, opcua.BadDecodingError
			}
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, opcua.BadDecodingError
			}

			// body
			switch ch.securityMode {
			case opcua.MessageSecurityModeSignAndEncrypt, opcua.MessageSecurityModeSign:
				cipherTextBlockSize := ch.localPrivateKey.Size()
				signatureSize := ch.remotePublicKey.Size()
				if cipherTextBlockSize > 256 {
					paddingHeaderSize = 2
					start := int(messageLength) - signatureSize - paddingHeaderSize
					paddingSize = int(binary.LittleEndian.Uint16(receiveBuffer[start : start+2]))
				} else {
					paddingHeaderSize = 1
					start := int(messageLength) - signatureSize - paddingHeaderSize
					paddingSize = int(receiveBuffer[start])
				}
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - paddingSize - paddingHeaderSize - signatureSize

			default:
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize // - ch.asymRemoteSignatureSize
			}

			m := plainHeaderSize + sequenceHeaderSize
			n := m + bodySize
			if _, err := bodyStream.Write(receiveBuffer[m:n]); err != nil {
				return nil, err
			}

			isFinal = messageType == opcua.MessageTypeOpenFinal

		case opcua.MessageTypeError, opcua.MessageTypeAbort:
			var statusCode uint32
			if err := decoder.ReadUInt32(&statusCode); err != nil {
				return nil, opcua.BadDecodingError
			}
			var unused string
			if err = decoder.ReadString(&unused); err != nil {
				return nil, opcua.BadDecodingError
			}
			ch.errCode = opcua.StatusCode(statusCode)
			return nil, opcua.StatusCode(statusCode)

		default:
			return nil, opcua.BadUnknownResponse
		}

		if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
			return nil, opcua.BadEncodingLimitsExceeded
		}
	}

	var nodeID opcua.NodeID
	if err := bodyDecoder.ReadNodeID(&nodeID); err != nil {
		return nil, opcua.BadDecodingError
	}
	var temp interface{}
	switch nodeID {

	// frequent
	case opcua.ObjectIDPublishResponseEncodingDefaultBinary:
		temp = new(opcua.PublishResponse)
	case opcua.ObjectIDReadResponseEncodingDefaultBinary:
		temp = new(opcua.ReadResponse)
	case opcua.ObjectIDBrowseResponseEncodingDefaultBinary:
		temp = new(opcua.BrowseResponse)
	case opcua.ObjectIDBrowseNextResponseEncodingDefaultBinary:
		temp = new(opcua.BrowseNextResponse)
	case opcua.ObjectIDTranslateBrowsePathsToNodeIDsResponseEncodingDefaultBinary:
		temp = new(opcua.TranslateBrowsePathsToNodeIDsResponse)
	case opcua.ObjectIDWriteResponseEncodingDefaultBinary:
		temp = new(opcua.WriteResponse)
	case opcua.ObjectIDCallResponseEncodingDefaultBinary:
		temp = new(opcua.CallResponse)
	case opcua.ObjectIDHistoryReadResponseEncodingDefaultBinary:
		temp = new(opcua.HistoryReadResponse)

	// moderate
	case opcua.ObjectIDGetEndpointsResponseEncodingDefaultBinary:
		temp = new(opcua.GetEndpointsResponse)
	case opcua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary:
		temp = new(opcua.OpenSecureChannelResponse)
	case opcua.ObjectIDCloseSecureChannelResponseEncodingDefaultBinary:
		temp = new(opcua.CloseSecureChannelResponse)
	case opcua.ObjectIDCreateSessionResponseEncodingDefaultBinary:
		temp = new(opcua.CreateSessionResponse)
	case opcua.ObjectIDActivateSessionResponseEncodingDefaultBinary:
		temp = new(opcua.ActivateSessionResponse)
	case opcua.ObjectIDCloseSessionResponseEncodingDefaultBinary:
		temp = new(opcua.CloseSessionResponse)
	case opcua.ObjectIDCreateMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(opcua.CreateMonitoredItemsResponse)
	case opcua.ObjectIDDeleteMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(opcua.DeleteMonitoredItemsResponse)
	case opcua.ObjectIDCreateSubscriptionResponseEncodingDefaultBinary:
		temp = new(opcua.CreateSubscriptionResponse)
	case opcua.ObjectIDDeleteSubscriptionsResponseEncodingDefaultBinary:
		temp = new(opcua.DeleteSubscriptionsResponse)
	case opcua.ObjectIDSetPublishingModeResponseEncodingDefaultBinary:
		temp = new(opcua.SetPublishingModeResponse)
	case opcua.ObjectIDServiceFaultEncodingDefaultBinary:
		temp = new(opcua.ServiceFault)

		// rare
	case opcua.ObjectIDModifyMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(opcua.ModifyMonitoredItemsResponse)
	case opcua.ObjectIDSetMonitoringModeResponseEncodingDefaultBinary:
		temp = new(opcua.SetMonitoringModeResponse)
	case opcua.ObjectIDSetTriggeringResponseEncodingDefaultBinary:
		temp = new(opcua.SetTriggeringResponse)
	case opcua.ObjectIDModifySubscriptionResponseEncodingDefaultBinary:
		temp = new(opcua.ModifySubscriptionResponse)
	case opcua.ObjectIDRepublishResponseEncodingDefaultBinary:
		temp = new(opcua.RepublishResponse)
	case opcua.ObjectIDTransferSubscriptionsResponseEncodingDefaultBinary:
		temp = new(opcua.TransferSubscriptionsResponse)
	case opcua.ObjectIDFindServersResponseEncodingDefaultBinary:
		temp = new(opcua.FindServersResponse)
	case opcua.ObjectIDFindServersOnNetworkResponseEncodingDefaultBinary:
		temp = new(opcua.FindServersOnNetworkResponse)
	case opcua.ObjectIDRegisterServerResponseEncodingDefaultBinary:
		temp = new(opcua.RegisterServerResponse)
	case opcua.ObjectIDRegisterServer2ResponseEncodingDefaultBinary:
		temp = new(opcua.RegisterServer2Response)
	case opcua.ObjectIDCancelResponseEncodingDefaultBinary:
		temp = new(opcua.CancelResponse)
	case opcua.ObjectIDAddNodesResponseEncodingDefaultBinary:
		temp = new(opcua.AddNodesResponse)
	case opcua.ObjectIDAddReferencesResponseEncodingDefaultBinary:
		temp = new(opcua.AddReferencesResponse)
	case opcua.ObjectIDDeleteNodesResponseEncodingDefaultBinary:
		temp = new(opcua.DeleteNodesResponse)
	case opcua.ObjectIDDeleteReferencesResponseEncodingDefaultBinary:
		temp = new(opcua.DeleteReferencesResponse)
	case opcua.ObjectIDRegisterNodesResponseEncodingDefaultBinary:
		temp = new(opcua.RegisterNodesResponse)
	case opcua.ObjectIDUnregisterNodesResponseEncodingDefaultBinary:
		temp = new(opcua.UnregisterNodesResponse)
	case opcua.ObjectIDQueryFirstResponseEncodingDefaultBinary:
		temp = new(opcua.QueryFirstResponse)
	case opcua.ObjectIDQueryNextResponseEncodingDefaultBinary:
		temp = new(opcua.QueryNextResponse)
	case opcua.ObjectIDHistoryUpdateResponseEncodingDefaultBinary:
		temp = new(opcua.HistoryUpdateResponse)
	default:
		return nil, opcua.BadDecodingError
	}

	// decode fields from message stream
	if err := bodyDecoder.Decode(temp); err != nil {
		return nil, opcua.BadDecodingError
	}
	res = temp.(opcua.ServiceResponse)

	if ch.trace {
		b, _ := json.MarshalIndent(res, "", " ")
		log.Printf("%s%s", reflect.TypeOf(res).Elem().Name(), b)
	}

	return res, nil
}

// handleResponse directs the response to the correct handler.
func (ch *clientSecureChannel) handleResponse(res opcua.ServiceResponse) error {
	ch.mapPendingResponses()
	hnd := res.Header().RequestHandle
	if op, ok := ch.pendingResponses[hnd]; ok {
		delete(ch.pendingResponses, hnd)
		select {
		case op.ResponseCh() <- res:
		default:
			fmt.Println("In handleResponse, responseCh was blocked.")
		}
		return nil
	}
	return opcua.BadUnknownResponse
}

// mapPendingResponses maps operations coming from pendingResponseCh.
func (ch *clientSecureChannel) mapPendingResponses() {
	for {
		select {
		case op := <-ch.pendingResponseCh:
			ch.pendingResponses[op.Request().Header().RequestHandle] = op
		default:
			return
		}
	}
}

// renewToken sends request to renew security token.
func (ch *clientSecureChannel) renewToken(ctx context.Context) error {
	request := &opcua.OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           opcua.SecurityTokenRequestTypeRenew,
		SecurityMode:          ch.securityMode,
		ClientNonce:           opcua.ByteString(getNextNonce(ch.securityPolicy.NonceSize())),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*opcua.OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return opcua.BadProtocolVersionUnsupported
	}

	ch.tokenLock.Lock()
	ch.tokenRenewalTime = time.Now().Add(time.Duration(response.SecurityToken.RevisedLifetime*75/100) * time.Millisecond)
	// ch.channelId = response.opcua.SecurityToken.ChannelID
	ch.tokenID = response.SecurityToken.TokenID
	ch.localNonce = []byte(request.ClientNonce)
	ch.remoteNonce = []byte(response.ServerNonce)
	ch.tokenLock.Unlock()
	return nil
}

// calculatePSHA calculates the pseudo random function.
func calculatePSHA(secret, seed []byte, sizeBytes int, securityPolicyURI string) []byte {
	var mac hash.Hash
	switch securityPolicyURI {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		mac = hmac.New(sha1.New, secret)
	default:
		mac = hmac.New(sha256.New, secret)
	}
	size := mac.Size()
	output := make([]byte, sizeBytes)
	a := seed
	iterations := (sizeBytes + size - 1) / size
	for i := 0; i < iterations; i++ {
		mac.Reset()
		mac.Write(a)
		buf := mac.Sum(nil)
		a = buf
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		buf2 := mac.Sum(nil)
		m := size * i
		n := sizeBytes - m
		if n > size {
			n = size
		}
		copy(output[m:m+n], buf2)
	}
	return output
}

// getNextRequestHandle gets next RequestHandle in sequence, skipping zero.
func (ch *clientSecureChannel) getNextRequestHandle() uint32 {
	ch.requestHandleLock.Lock()
	defer ch.requestHandleLock.Unlock()
	if ch.requestHandle == math.MaxUint32 {
		ch.requestHandle = 0
	}
	ch.requestHandle++
	return ch.requestHandle
}

// getNextSequenceNumber gets next SequenceNumber in sequence, skipping zero.
func (ch *clientSecureChannel) getNextSequenceNumber() uint32 {
	ch.sequenceNumberLock.Lock()
	defer ch.sequenceNumberLock.Unlock()
	if ch.sequenceNumber == math.MaxUint32 {
		ch.sequenceNumber = 0
	}
	ch.sequenceNumber++
	return ch.sequenceNumber
}

// getNextNonce gets next random nonce of requested length.
func getNextNonce(length int) []byte {
	var nonce = make([]byte, length)
	rand.Read(nonce)
	return nonce
}

// Write sends a chunk to the remote endpoint.
func (ch *clientSecureChannel) Write(p []byte) (int, error) {
	return ch.conn.Write(p)
}

// Read receives a chunk from the remote endpoint.
func (ch *clientSecureChannel) Read(p []byte) (int, error) {
	if ch.conn == nil {
		return 0, opcua.BadSecureChannelClosed
	}

	var err error
	num := 0
	n := 0
	count := 8
	for num < count {
		n, err = ch.conn.Read(p[num:count])
		if err != nil || n == 0 {
			return num, err
		}
		num += n
	}

	count = int(binary.LittleEndian.Uint32(p[4:8]))
	for num < count {
		n, err = ch.conn.Read(p[num:count])
		if err != nil || n == 0 {
			return num, err
		}
		num += n
	}

	return num, err
}
