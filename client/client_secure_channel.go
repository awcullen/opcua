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

	"github.com/awcullen/opcua/ua"
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
	localDescription                   ua.ApplicationDescription
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
	localPrivateKeySize        int
	remotePublicKeySize        int
	localNonce                 []byte
	remoteNonce                []byte
	channelID                  uint32
	tokenID                    uint32
	tokenLock                  sync.RWMutex
	authenticationToken        ua.NodeID
	securityPolicyURI          string
	securityPolicy             ua.SecurityPolicy
	securityMode               ua.MessageSecurityMode
	namespaceURIs              []string
	serverURIs                 []string
	cancellation               chan struct{}
	errCode                    ua.StatusCode
	sendingSemaphore           sync.Mutex
	receivingSemaphore         sync.Mutex
	pendingResponseCh          chan *ua.ServiceOperation
	pendingResponses           map[uint32]*ua.ServiceOperation
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
	symEncryptingBlockCipher   cipher.Block
	symDecryptingBlockCipher   cipher.Block
	trace                      bool
}

// newClientSecureChannel initializes a new instance of the secure channel.
func newClientSecureChannel(
	localDescription ua.ApplicationDescription,
	localCertificate []byte,
	localPrivateKey *rsa.PrivateKey,
	endpointURL string,
	securityPolicyURI string,
	securityMode ua.MessageSecurityMode,
	remoteCertificate []byte,
	connectTimeout int64,
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
func (ch *clientSecureChannel) SetAuthenticationToken(value ua.NodeID) {
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
func (ch *clientSecureChannel) Request(ctx context.Context, req ua.ServiceRequest) (ua.ServiceResponse, error) {
	header := req.Header()
	header.Timestamp = time.Now()
	header.RequestHandle = ch.getNextRequestHandle()
	header.AuthenticationToken = ch.authenticationToken
	if header.TimeoutHint == 0 {
		header.TimeoutHint = defaultTimeoutHint
	}
	var operation = ua.NewServiceOperation(req, make(chan ua.ServiceResponse, 1))
	ch.pendingResponseCh <- operation
	ctx, cancel := context.WithDeadline(ctx, header.Timestamp.Add(time.Duration(header.TimeoutHint)*time.Millisecond))
	err := ch.sendRequest(ctx, operation)
	if err != nil {
		cancel()
		return nil, err
	}
	select {
	case res := <-operation.ResponseCh():
		if sr := res.Header().ServiceResult; sr != ua.Good {
			cancel()
			return nil, sr
		}
		cancel()
		return res, nil
	case <-ctx.Done():
		cancel()
		return nil, ua.BadRequestTimeout
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
			return ua.BadSecurityChecksFailed
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
	var writer = ua.NewWriter(buf)
	var enc = ua.NewBinaryEncoder(writer, ch)
	enc.WriteUInt32(ua.MessageTypeHello)
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

	// if ch.trace {
	// 	log.Printf("Hello{\"Version\":%d,\"ReceiveBufferSize\":%d,\"SendBufferSize\":%d,\"MaxMessageSize\":%d,\"MaxChunkCount\":%d,\"EndpointURL\":\"%s\"}\n", protocolVersion, defaultBufferSize, defaultBufferSize, defaultMaxMessageSize, defaultMaxChunkCount, ch.endpointURL)
	// }

	_, err = ch.Read(buf)
	if err != nil {
		return err
	}

	var reader = bytes.NewReader(buf)
	var dec = ua.NewBinaryDecoder(reader, ch)
	var msgType uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return err
	}
	var msgLen uint32
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return err
	}

	switch msgType {
	case ua.MessageTypeAck:
		if msgLen < 28 {
			return ua.BadDecodingError
		}
		var remoteProtocolVersion uint32
		if err := dec.ReadUInt32(&remoteProtocolVersion); err != nil {
			return err
		}
		if remoteProtocolVersion < protocolVersion {
			return ua.BadProtocolVersionUnsupported
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
		// if ch.trace {
		// 	log.Printf("Ack{\"Version\":%d,\"ReceiveBufferSize\":%d,\"SendBufferSize\":%d,\"MaxMessageSize\":%d,\"MaxChunkCount\":%d}\n", remoteProtocolVersion, ch.sendBufferSize, ch.receiveBufferSize, ch.maxMessageSize, ch.maxChunkCount)
		// }

	case ua.MessageTypeError:
		if msgLen < 16 {
			return ua.BadDecodingError
		}
		var remoteCode uint32
		if err := dec.ReadUInt32(&remoteCode); err != nil {
			return err
		}
		var unused string
		if err = dec.ReadString(&unused); err != nil {
			return err
		}
		return ua.StatusCode(remoteCode)

	default:
		return ua.BadDecodingError
	}

	// setSecurityPolicy
	switch ch.securityPolicyURI {
	case ua.SecurityPolicyURINone:
		ch.securityPolicy = new(ua.SecurityPolicyNone)

	case ua.SecurityPolicyURIBasic128Rsa15:
		ch.securityPolicy = new(ua.SecurityPolicyBasic128Rsa15)

	case ua.SecurityPolicyURIBasic256:
		ch.securityPolicy = new(ua.SecurityPolicyBasic256)

	case ua.SecurityPolicyURIBasic256Sha256:
		ch.securityPolicy = new(ua.SecurityPolicyBasic256Sha256)

	case ua.SecurityPolicyURIAes128Sha256RsaOaep:
		ch.securityPolicy = new(ua.SecurityPolicyAes128Sha256RsaOaep)

	case ua.SecurityPolicyURIAes256Sha256RsaPss:
		ch.securityPolicy = new(ua.SecurityPolicyAes256Sha256RsaPss)

	default:
		return ua.BadSecurityPolicyRejected
	}

	ch.localSigningKey = make([]byte, ch.securityPolicy.SymSignatureKeySize())
	ch.localEncryptingKey = make([]byte, ch.securityPolicy.SymEncryptionKeySize())
	ch.localInitializationVector = make([]byte, ch.securityPolicy.SymEncryptionBlockSize())
	ch.remoteSigningKey = make([]byte, ch.securityPolicy.SymSignatureKeySize())
	ch.remoteEncryptingKey = make([]byte, ch.securityPolicy.SymEncryptionKeySize())
	ch.remoteInitializationVector = make([]byte, ch.securityPolicy.SymEncryptionBlockSize())

	switch ch.securityMode {
	case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
		if ch.localPrivateKey == nil {
			return ua.BadSecurityChecksFailed
		}
		ch.localPrivateKeySize = ch.localPrivateKey.Size()
		if ch.remotePublicKey == nil {
			return ua.BadSecurityChecksFailed
		}
		ch.remotePublicKeySize = ch.remotePublicKey.Size()
	}

	ch.pendingResponseCh = make(chan *ua.ServiceOperation, 32)
	ch.pendingResponses = make(map[uint32]*ua.ServiceOperation)
	ch.cancellation = make(chan struct{})
	ch.channelID = 0
	ch.tokenID = 0
	ch.sendingTokenID = 0
	ch.receivingTokenID = 0

	go ch.responseWorker()

	request := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           ua.SecurityTokenRequestTypeIssue,
		SecurityMode:          ch.securityMode,
		ClientNonce:           ua.ByteString(getNextNonce(ch.securityPolicy.NonceSize())),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*ua.OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return ua.BadProtocolVersionUnsupported
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
	var request = &ua.CloseSecureChannelRequest{}
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
func (ch *clientSecureChannel) sendRequest(ctx context.Context, op *ua.ServiceOperation) error {
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
	case *ua.OpenSecureChannelRequest:
		err := ch.sendOpenSecureChannelRequest(ctx, req)
		if err != nil {
			return err
		}
	case *ua.CloseSecureChannelRequest:
		err := ch.sendServiceRequest(ctx, req)
		if err != nil {
			return err
		}
		// send a success response to ourselves (the server will just close it's socket).
		select {
		case op.ResponseCh() <- &ua.CloseSecureChannelResponse{ResponseHeader: ua.ResponseHeader{RequestHandle: req.RequestHandle, Timestamp: time.Now()}}:
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
func (ch *clientSecureChannel) sendOpenSecureChannelRequest(ctx context.Context, request *ua.OpenSecureChannelRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&sendBuffer)

	var bodyEncoder = ua.NewBinaryEncoder(bodyStream, ch)

	if err := bodyEncoder.WriteNodeID(ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary); err != nil {
		return ua.BadEncodingError
	}

	if err := bodyEncoder.Encode(request); err != nil {
		return ua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return ua.BadEncodingLimitsExceeded
	}

	// write chunks
	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return ua.BadEncodingLimitsExceeded
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
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
			plainHeaderSize = 16 + len(ch.securityPolicyURI) + 28 + len(ch.localCertificate)
			signatureSize = ch.localPrivateKeySize
			cipherTextBlockSize = ch.remotePublicKeySize
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
			plainHeaderSize = 16 + len(ch.securityPolicyURI) + 8
			signatureSize = 0
			cipherTextBlockSize = 1
			plainTextBlockSize = 1
			paddingHeaderSize = 0
			paddingSize = 0
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize
		}

		var stream = ua.NewWriter(sendBuffer)
		var encoder = ua.NewBinaryEncoder(stream, ch)

		// header
		encoder.WriteUInt32(ua.MessageTypeOpenFinal)
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// asymmetric security header
		encoder.WriteString(ch.securityPolicyURI)
		switch ch.securityMode {
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
			encoder.WriteByteArray(ch.localCertificate)
			thumbprint := sha1.Sum(ch.remoteCertificate)
			encoder.WriteByteArray(thumbprint[:])
		default:
			encoder.WriteByteArray(nil)
			encoder.WriteByteArray(nil)
		}

		if plainHeaderSize != int(stream.Len()) {
			return ua.BadEncodingError
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
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
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
			return ua.BadEncodingError
		}

		// sign
		switch ch.securityMode {
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
			signature, err := ch.securityPolicy.RSASign(ch.localPrivateKey, stream.Bytes())
			if err != nil {
				return err
			}
			if len(signature) != signatureSize {
				return ua.BadEncodingError
			}
			_, err = stream.Write(signature)
			if err != nil {
				return err
			}
		}

		// encrypt
		switch ch.securityMode {
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
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
					return ua.BadEncodingError
				}
				copy(encryptionBuffer[jj:], cipherText)
				jj += cipherTextBlockSize
			}
			if jj != chunkSize {
				return ua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.Write(encryptionBuffer[:chunkSize])
			if err != nil {
				return err
			}

		default:

			if stream.Len() != chunkSize {
				return ua.BadEncodingError
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
func (ch *clientSecureChannel) sendServiceRequest(ctx context.Context, request ua.ServiceRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&sendBuffer)

	var bodyEncoder = ua.NewBinaryEncoder(bodyStream, ch)

	switch req := request.(type) {

	// frequent
	case *ua.PublishRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDPublishRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ReadRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDReadRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.BrowseRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDBrowseRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.BrowseNextRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDBrowseNextRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.TranslateBrowsePathsToNodeIDsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDTranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.WriteRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDWriteRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CallRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCallRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.HistoryReadRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDHistoryReadRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}

	// moderate
	case *ua.GetEndpointsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDGetEndpointsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.OpenSecureChannelRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CloseSecureChannelRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCloseSecureChannelRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateSessionRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateSessionRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ActivateSessionRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDActivateSessionRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CloseSessionRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCloseSessionRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateSubscriptionRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateSubscriptionRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteSubscriptionsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteSubscriptionsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetPublishingModeRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetPublishingModeRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}

		// rare
	case *ua.ModifyMonitoredItemsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDModifyMonitoredItemsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetMonitoringModeRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetMonitoringModeRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetTriggeringRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetTriggeringRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ModifySubscriptionRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDModifySubscriptionRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RepublishRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRepublishRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.TransferSubscriptionsRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDTransferSubscriptionsRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.FindServersRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDFindServersRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.FindServersOnNetworkRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDFindServersOnNetworkRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterServerRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterServerRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterServer2Request:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterServer2RequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CancelRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCancelRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.AddNodesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDAddNodesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.AddReferencesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDAddReferencesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteNodesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteNodesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteReferencesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteReferencesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterNodesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterNodesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.UnregisterNodesRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDUnregisterNodesRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.QueryFirstRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDQueryFirstRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.QueryNextRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDQueryNextRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	case *ua.HistoryUpdateRequest:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDHistoryUpdateRequestEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(req); err != nil {
			return ua.BadEncodingError
		}
	default:
		return ua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return ua.BadEncodingLimitsExceeded
	}

	var chunkCount int
	var bodyCount = int(bodyStream.Len())
	var signatureSize = ch.securityPolicy.SymSignatureSize()
	var encryptionBlockSize = ch.securityPolicy.SymEncryptionBlockSize()

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return ua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		switch ch.securityMode {
		case ua.MessageSecurityModeSignAndEncrypt:
			plainHeaderSize = 16
			if encryptionBlockSize > 256 {
				paddingHeaderSize = 2
			} else {
				paddingHeaderSize = 1
			}
			maxBodySize = (((int(ch.sendBufferSize) - plainHeaderSize) / encryptionBlockSize) * encryptionBlockSize) - sequenceHeaderSize - paddingHeaderSize - signatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
				paddingSize = (encryptionBlockSize - ((sequenceHeaderSize + bodySize + paddingHeaderSize + signatureSize) % encryptionBlockSize)) % encryptionBlockSize
			} else {
				bodySize = maxBodySize
				paddingSize = 0
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + paddingSize + paddingHeaderSize + signatureSize

		default:
			plainHeaderSize = 16
			paddingHeaderSize = 0
			paddingSize = 0
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize
		}

		var stream = ua.NewWriter(sendBuffer)
		var encoder = ua.NewBinaryEncoder(stream, ch)

		// header
		if bodyCount > bodySize {
			encoder.WriteUInt32(ua.MessageTypeChunk)
		} else {
			encoder.WriteUInt32(ua.MessageTypeFinal)
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
			case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
				// (re)create security keys for signing, encrypting
				localSecurityKey := calculatePSHA(ch.remoteNonce, ch.localNonce, len(ch.localSigningKey)+len(ch.localEncryptingKey)+len(ch.localInitializationVector), ch.securityPolicyURI)
				jj := copy(ch.localSigningKey, localSecurityKey)
				jj += copy(ch.localEncryptingKey, localSecurityKey[jj:])
				copy(ch.localInitializationVector, localSecurityKey[jj:])

				// update signer and encrypter with new symmetric keys
				ch.symSignHMAC = ch.securityPolicy.SymHMACFactory(ch.localSigningKey)
				if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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
		if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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
		case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
			ch.symSignHMAC.Reset()
			_, err := ch.symSignHMAC.Write(stream.Bytes())
			if err != nil {
				return err
			}
			signature := ch.symSignHMAC.Sum(nil)
			stream.Write(signature)
		}

		// encrypt
		if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
			span := stream.Bytes()[plainHeaderSize:]
			if len(span)%ch.symEncryptingBlockCipher.BlockSize() != 0 {
				return ua.BadEncodingError
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
			if ch.errCode == ua.Good {
				if ec, ok := err.(ua.StatusCode); ok {
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
func (ch *clientSecureChannel) readResponse() (ua.ServiceResponse, error) {
	ch.receivingSemaphore.Lock()
	defer ch.receivingSemaphore.Unlock()
	var res ua.ServiceResponse
	var paddingHeaderSize int
	var plainHeaderSize int
	var bodySize int
	var paddingSize int
	signatureSize := ch.securityPolicy.SymSignatureSize()

	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var receiveBuffer = *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&receiveBuffer)

	var bodyDecoder = ua.NewBinaryDecoder(bodyStream, ch)

	// read chunks
	var chunkCount int32
	var isFinal bool

	for !isFinal {
		chunkCount++
		if i := int32(ch.maxChunkCount); i > 0 && chunkCount > i {
			return nil, ua.BadEncodingLimitsExceeded
		}

		count, err := ch.Read(receiveBuffer)
		if err != nil || count == 0 {
			return nil, ua.BadSecureChannelClosed
		}

		var stream = bytes.NewReader(receiveBuffer[0:count])
		var decoder = ua.NewBinaryDecoder(stream, ch)

		var messageType uint32
		if err := decoder.ReadUInt32(&messageType); err != nil {
			return nil, ua.BadDecodingError
		}
		var messageLength uint32
		if err := decoder.ReadUInt32(&messageLength); err != nil {
			return nil, ua.BadDecodingError
		}

		if count != int(messageLength) {
			return nil, ua.BadDecodingError
		}

		switch messageType {
		case ua.MessageTypeChunk, ua.MessageTypeFinal:
			// header
			var channelID uint32
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, ua.BadDecodingError
			}
			if channelID != ch.channelID {
				return nil, ua.BadTCPSecureChannelUnknown
			}

			// symmetric security header
			var tokenID uint32
			if err := decoder.ReadUInt32(&tokenID); err != nil {
				return nil, ua.BadDecodingError
			}

			// detect new token
			ch.tokenLock.RLock()
			if tokenID != ch.receivingTokenID {
				ch.receivingTokenID = tokenID

				switch ch.securityMode {
				case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
					// (re)create remote security keys for verifying, decrypting
					remoteSecurityKey := calculatePSHA(ch.localNonce, ch.remoteNonce, len(ch.remoteSigningKey)+len(ch.remoteEncryptingKey)+len(ch.remoteInitializationVector), ch.securityPolicyURI)
					jj := copy(ch.remoteSigningKey, remoteSecurityKey)
					jj += copy(ch.remoteEncryptingKey, remoteSecurityKey[jj:])
					copy(ch.remoteInitializationVector, remoteSecurityKey[jj:])

					// update verifier and decrypter with new symmetric keys
					ch.symVerifyHMAC = ch.securityPolicy.SymHMACFactory(ch.remoteSigningKey)
					if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
						ch.symDecryptingBlockCipher, _ = aes.NewCipher(ch.remoteEncryptingKey)
					}
				}
			}
			ch.tokenLock.RUnlock()

			plainHeaderSize = 16
			// decrypt
			if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
				span := receiveBuffer[plainHeaderSize:count]
				if len(span)%ch.symDecryptingBlockCipher.BlockSize() != 0 {
					return nil, ua.BadDecodingError
				}
				cipher.NewCBCDecrypter(ch.symDecryptingBlockCipher, ch.remoteInitializationVector).CryptBlocks(span, span)
			}

			// verify
			switch ch.securityMode {
			case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
				sigStart := count - signatureSize
				ch.symVerifyHMAC.Reset()
				ch.symVerifyHMAC.Write(receiveBuffer[:sigStart])
				sig := ch.symVerifyHMAC.Sum(nil)
				if !hmac.Equal(sig, receiveBuffer[sigStart:count]) {
					return nil, ua.BadSecurityChecksFailed
				}
			}

			// read sequence header
			var unused uint32
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, ua.BadDecodingError
			}

			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, ua.BadDecodingError
			}

			// body
			switch ch.securityMode {
			case ua.MessageSecurityModeSignAndEncrypt:
				if ch.securityPolicy.SymEncryptionBlockSize() > 256 {
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
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - signatureSize
			}

			m := plainHeaderSize + sequenceHeaderSize
			n := m + bodySize
			_, err = bodyStream.Write(receiveBuffer[m:n])
			if err != nil {
				return nil, err
			}

			isFinal = messageType == ua.MessageTypeFinal

		case ua.MessageTypeOpenFinal:
			// header
			var unused1 uint32
			if err = decoder.ReadUInt32(&unused1); err != nil {
				return nil, ua.BadDecodingError
			}
			// asymmetric header
			var unused2 string
			if err = decoder.ReadString(&unused2); err != nil {
				return nil, ua.BadDecodingError
			}
			var unused3 ua.ByteString
			if err := decoder.ReadByteString(&unused3); err != nil {
				return nil, ua.BadDecodingError
			}
			if err := decoder.ReadByteString(&unused3); err != nil {
				return nil, ua.BadDecodingError
			}
			plainHeaderSize = count - stream.Len()

			// decrypt
			switch ch.securityMode {
			case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
				cipherTextBlockSize := ch.localPrivateKeySize
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
			case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
				// verify with remote public key.
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.remotePublicKeySize
				err := ch.securityPolicy.RSAVerify(ch.remotePublicKey, receiveBuffer[:sigStart], receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, ua.BadDecodingError
				}
			}

			// sequence header
			var unused uint32
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, ua.BadDecodingError
			}
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, ua.BadDecodingError
			}

			// body
			switch ch.securityMode {
			case ua.MessageSecurityModeSignAndEncrypt, ua.MessageSecurityModeSign:
				cipherTextBlockSize := ch.localPrivateKeySize
				signatureSize := ch.remotePublicKeySize
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

			isFinal = messageType == ua.MessageTypeOpenFinal

		case ua.MessageTypeError, ua.MessageTypeAbort:
			var statusCode uint32
			if err := decoder.ReadUInt32(&statusCode); err != nil {
				return nil, ua.BadDecodingError
			}
			var unused string
			if err = decoder.ReadString(&unused); err != nil {
				return nil, ua.BadDecodingError
			}
			ch.errCode = ua.StatusCode(statusCode)
			return nil, ua.StatusCode(statusCode)

		default:
			return nil, ua.BadUnknownResponse
		}

		if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
			return nil, ua.BadEncodingLimitsExceeded
		}
	}

	var nodeID ua.NodeID
	if err := bodyDecoder.ReadNodeID(&nodeID); err != nil {
		return nil, ua.BadDecodingError
	}
	var temp interface{}
	switch nodeID {

	// frequent
	case ua.ObjectIDPublishResponseEncodingDefaultBinary:
		temp = new(ua.PublishResponse)
	case ua.ObjectIDReadResponseEncodingDefaultBinary:
		temp = new(ua.ReadResponse)
	case ua.ObjectIDBrowseResponseEncodingDefaultBinary:
		temp = new(ua.BrowseResponse)
	case ua.ObjectIDBrowseNextResponseEncodingDefaultBinary:
		temp = new(ua.BrowseNextResponse)
	case ua.ObjectIDTranslateBrowsePathsToNodeIDsResponseEncodingDefaultBinary:
		temp = new(ua.TranslateBrowsePathsToNodeIDsResponse)
	case ua.ObjectIDWriteResponseEncodingDefaultBinary:
		temp = new(ua.WriteResponse)
	case ua.ObjectIDCallResponseEncodingDefaultBinary:
		temp = new(ua.CallResponse)
	case ua.ObjectIDHistoryReadResponseEncodingDefaultBinary:
		temp = new(ua.HistoryReadResponse)

	// moderate
	case ua.ObjectIDGetEndpointsResponseEncodingDefaultBinary:
		temp = new(ua.GetEndpointsResponse)
	case ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary:
		temp = new(ua.OpenSecureChannelResponse)
	case ua.ObjectIDCloseSecureChannelResponseEncodingDefaultBinary:
		temp = new(ua.CloseSecureChannelResponse)
	case ua.ObjectIDCreateSessionResponseEncodingDefaultBinary:
		temp = new(ua.CreateSessionResponse)
	case ua.ObjectIDActivateSessionResponseEncodingDefaultBinary:
		temp = new(ua.ActivateSessionResponse)
	case ua.ObjectIDCloseSessionResponseEncodingDefaultBinary:
		temp = new(ua.CloseSessionResponse)
	case ua.ObjectIDCreateMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(ua.CreateMonitoredItemsResponse)
	case ua.ObjectIDDeleteMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(ua.DeleteMonitoredItemsResponse)
	case ua.ObjectIDCreateSubscriptionResponseEncodingDefaultBinary:
		temp = new(ua.CreateSubscriptionResponse)
	case ua.ObjectIDDeleteSubscriptionsResponseEncodingDefaultBinary:
		temp = new(ua.DeleteSubscriptionsResponse)
	case ua.ObjectIDSetPublishingModeResponseEncodingDefaultBinary:
		temp = new(ua.SetPublishingModeResponse)
	case ua.ObjectIDServiceFaultEncodingDefaultBinary:
		temp = new(ua.ServiceFault)

		// rare
	case ua.ObjectIDModifyMonitoredItemsResponseEncodingDefaultBinary:
		temp = new(ua.ModifyMonitoredItemsResponse)
	case ua.ObjectIDSetMonitoringModeResponseEncodingDefaultBinary:
		temp = new(ua.SetMonitoringModeResponse)
	case ua.ObjectIDSetTriggeringResponseEncodingDefaultBinary:
		temp = new(ua.SetTriggeringResponse)
	case ua.ObjectIDModifySubscriptionResponseEncodingDefaultBinary:
		temp = new(ua.ModifySubscriptionResponse)
	case ua.ObjectIDRepublishResponseEncodingDefaultBinary:
		temp = new(ua.RepublishResponse)
	case ua.ObjectIDTransferSubscriptionsResponseEncodingDefaultBinary:
		temp = new(ua.TransferSubscriptionsResponse)
	case ua.ObjectIDFindServersResponseEncodingDefaultBinary:
		temp = new(ua.FindServersResponse)
	case ua.ObjectIDFindServersOnNetworkResponseEncodingDefaultBinary:
		temp = new(ua.FindServersOnNetworkResponse)
	case ua.ObjectIDRegisterServerResponseEncodingDefaultBinary:
		temp = new(ua.RegisterServerResponse)
	case ua.ObjectIDRegisterServer2ResponseEncodingDefaultBinary:
		temp = new(ua.RegisterServer2Response)
	case ua.ObjectIDCancelResponseEncodingDefaultBinary:
		temp = new(ua.CancelResponse)
	case ua.ObjectIDAddNodesResponseEncodingDefaultBinary:
		temp = new(ua.AddNodesResponse)
	case ua.ObjectIDAddReferencesResponseEncodingDefaultBinary:
		temp = new(ua.AddReferencesResponse)
	case ua.ObjectIDDeleteNodesResponseEncodingDefaultBinary:
		temp = new(ua.DeleteNodesResponse)
	case ua.ObjectIDDeleteReferencesResponseEncodingDefaultBinary:
		temp = new(ua.DeleteReferencesResponse)
	case ua.ObjectIDRegisterNodesResponseEncodingDefaultBinary:
		temp = new(ua.RegisterNodesResponse)
	case ua.ObjectIDUnregisterNodesResponseEncodingDefaultBinary:
		temp = new(ua.UnregisterNodesResponse)
	case ua.ObjectIDQueryFirstResponseEncodingDefaultBinary:
		temp = new(ua.QueryFirstResponse)
	case ua.ObjectIDQueryNextResponseEncodingDefaultBinary:
		temp = new(ua.QueryNextResponse)
	case ua.ObjectIDHistoryUpdateResponseEncodingDefaultBinary:
		temp = new(ua.HistoryUpdateResponse)
	default:
		return nil, ua.BadDecodingError
	}

	// decode fields from message stream
	if err := bodyDecoder.Decode(temp); err != nil {
		return nil, ua.BadDecodingError
	}
	res = temp.(ua.ServiceResponse)

	if ch.trace {
		b, _ := json.MarshalIndent(res, "", " ")
		log.Printf("%s%s", reflect.TypeOf(res).Elem().Name(), b)
	}

	return res, nil
}

// handleResponse directs the response to the correct handler.
func (ch *clientSecureChannel) handleResponse(res ua.ServiceResponse) error {
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
	return ua.BadUnknownResponse
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
	request := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           ua.SecurityTokenRequestTypeRenew,
		SecurityMode:          ch.securityMode,
		ClientNonce:           ua.ByteString(getNextNonce(ch.securityPolicy.NonceSize())),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*ua.OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return ua.BadProtocolVersionUnsupported
	}

	ch.tokenLock.Lock()
	ch.tokenRenewalTime = time.Now().Add(time.Duration(response.SecurityToken.RevisedLifetime*75/100) * time.Millisecond)
	// ch.channelId = response.ua.SecurityToken.ChannelID
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
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
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
		return 0, ua.BadSecureChannelClosed
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
