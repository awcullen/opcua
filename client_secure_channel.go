// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

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

	"github.com/djherbis/buffer"
)

const (
	// defaultTimeoutHint is the default number of milliseconds before a request is cancelled. (15 sec)
	defaultTimeoutHint uint32 = 15000
	// defaultDiagnosticsHint is the default diagnostic hint that is sent in a request. (None)
	defaultDiagnosticsHint uint32 = 0x00000000
	// defaultTokenRequestedLifetime is the number of milliseconds before a security token is expired. (60 min)
	defaultTokenRequestedLifetime uint32 = 3600000
	// sequenceHeaderSize is the size of the sequence header
	sequenceHeaderSize int = 8
	// protocolVersion documents the version of binary protocol that this library supports.
	protocolVersion uint32 = 0
	// defaultBufferSize sets the default size of the send and receive buffers.
	defaultBufferSize uint32 = 64 * 1024
	// defaultMaxMessageSize sets the limit on the size of messages that may be accepted.
	defaultMaxMessageSize uint32 = 16 * 1024 * 1024
	// defaultMaxChunkCount sets the limit on the number of message chunks that may be accepted.
	defaultMaxChunkCount uint32 = 4 * 1024
	// minBufferSize sets the minimum buffer size
	minBufferSize int32 = 8 * 1024
	// defaultConnectTimeout sets the number of milliseconds to wait for a connection response.
	defaultConnectTimeout int64 = 5000
)

// clientSecureChannelOptions contains the secure channel options.
type clientSecureChannelOptions struct {
	// The time in milliseconds before a request is cancelled.
	TimeoutHint uint32
	// A bit mask that identifies the types of vendor-specific diagnostics to be returned in diagnosticInfo response parameters.
	DiagnosticsHint uint32
	// The time in milliseconds before a security token is expired.
	TokenLifetime uint32
	// The application instance certificate.
	ApplicationCertificate tls.Certificate
	// CertFile               string
	// // The private key of the application instance certificate.
	// KeyFile string
	// // The trusted server certificates or certificate authorities. If empty string, CA certs of OS are used instead.
	TrustedCertsFile string
	// Suppress check if server certificate has incorrect hostname.
	SuppressHostNameInvalid bool
	// Suppress check if server certificate has expired or is not yet valid.
	SuppressCertificateExpired bool
	// Suppress check if server certificate has authority found in the RootCAs pool.
	SuppressCertificateChainIncomplete bool
	// The number of milliseconds to wait for a connection response.
	ConnectTimeout int64
	// Trace all requests and responses to StdOut.
	Trace bool
}

// newClientSecureChannelOptions initializes a options structure with default values.
func newClientSecureChannelOptions() clientSecureChannelOptions {
	return clientSecureChannelOptions{
		TimeoutHint:     defaultTimeoutHint,
		DiagnosticsHint: defaultDiagnosticsHint,
		TokenLifetime:   defaultTokenRequestedLifetime,
		ConnectTimeout:  defaultConnectTimeout,
		Trace:           false,
	}
}

// clientSecureChannel implements a secure channel for binary data over Tcp.
type clientSecureChannel struct {
	sync.RWMutex
	localDescription       *ApplicationDescription
	applicationCertificate tls.Certificate
	timeoutHint            uint32
	diagnosticsHint        uint32
	tokenRequestedLifetime uint32
	//
	endpointURL       string
	receiveBufferSize uint32
	sendBufferSize    uint32
	maxMessageSize    uint32
	maxChunkCount     uint32
	conn              net.Conn
	connectTimeout    int64
	//
	// certFile                           string
	// keyFile                            string
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
	authenticationToken        NodeID
	securityPolicyURI          string
	securityPolicy             SecurityPolicy
	securityToken              securityToken
	securityMode               MessageSecurityMode
	namespaceURIs              []string
	serverURIs                 []string
	cancellation               chan struct{}
	errCode                    StatusCode
	sendingSemaphore           sync.Mutex
	receivingSemaphore         sync.Mutex
	pendingResponseCh          chan *serviceOperation
	pendingResponses           map[uint32]*serviceOperation
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
func newClientSecureChannel(localDescription *ApplicationDescription, localCertificate []byte, localPrivateKey *rsa.PrivateKey, endpoint *EndpointDescription, options clientSecureChannelOptions) *clientSecureChannel {
	ch := &clientSecureChannel{
		endpointURL:            endpoint.EndpointURL,
		connectTimeout:         options.ConnectTimeout,
		applicationCertificate: options.ApplicationCertificate,
		// certFile:                           options.CertFile,
		// keyFile:                            options.KeyFile,
		trustedCertsFile:                   options.TrustedCertsFile,
		suppressHostNameInvalid:            options.SuppressHostNameInvalid,
		suppressCertificateExpired:         options.SuppressCertificateExpired,
		suppressCertificateChainIncomplete: options.SuppressCertificateChainIncomplete,
		localDescription:                   localDescription,
		localCertificate:                   localCertificate,
		localPrivateKey:                    localPrivateKey,
		securityPolicyURI:                  endpoint.SecurityPolicyURI,
		securityMode:                       endpoint.SecurityMode,
		remoteCertificate:                  []byte(endpoint.ServerCertificate),
		timeoutHint:                        options.TimeoutHint,
		diagnosticsHint:                    options.DiagnosticsHint,
		tokenRequestedLifetime:             options.TokenLifetime,
		namespaceURIs:                      []string{"http://opcfoundation.org/UA/"},
		serverURIs:                         []string{},
		trace:                              options.Trace,
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
func (ch *clientSecureChannel) SetAuthenticationToken(value NodeID) {
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
func (ch *clientSecureChannel) Request(ctx context.Context, req ServiceRequest) (ServiceResponse, error) {
	header := req.Header()
	header.Timestamp = time.Now()
	header.RequestHandle = ch.getNextRequestHandle()
	header.AuthenticationToken = ch.authenticationToken
	if header.TimeoutHint == 0 {
		header.TimeoutHint = defaultTimeoutHint
	}
	var operation = newServiceOperation(req, make(chan ServiceResponse, 1))
	ch.pendingResponseCh <- operation
	ctx, cancel := context.WithDeadline(ctx, header.Timestamp.Add(time.Duration(header.TimeoutHint)*time.Millisecond))
	err := ch.sendRequest(ctx, operation)
	if err != nil {
		cancel()
		return nil, err
	}
	select {
	case res := <-operation.ResponseCh():
		if sr := res.Header().ServiceResult; sr != Good {
			cancel()
			return nil, sr
		}
		cancel()
		return res, nil
	case <-ctx.Done():
		cancel()
		return nil, BadRequestTimeout
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
			return BadSecurityChecksFailed
		}
		_, err = ValidateServerCertificate(cert, remoteURL.Hostname(), ch.trustedCertsFile, ch.suppressHostNameInvalid, ch.suppressCertificateExpired, ch.suppressCertificateChainIncomplete)
		if err != nil {
			return err
		}
	}

	ch.conn, err = net.DialTimeout("tcp", remoteURL.Host, time.Duration(ch.connectTimeout)*time.Millisecond)
	if err != nil {
		return err
	}

	var buf = bytesPool.Get().([]byte)
	defer bytesPool.Put(buf)
	var writer = NewWriter(buf)
	var enc = NewBinaryEncoder(writer, ch)
	enc.WriteUInt32(messageTypeHello)
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
	var dec = NewBinaryDecoder(reader, ch)
	var msgType uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return err
	}
	var msgLen uint32
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return err
	}

	switch msgType {
	case messageTypeAck:
		if msgLen < 28 {
			return BadDecodingError
		}
		var remoteProtocolVersion uint32
		if err := dec.ReadUInt32(&remoteProtocolVersion); err != nil {
			return err
		}
		if remoteProtocolVersion < protocolVersion {
			return BadProtocolVersionUnsupported
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

	case messageTypeError:
		if msgLen < 16 {
			return BadDecodingError
		}
		var remoteCode uint32
		if err := dec.ReadUInt32(&remoteCode); err != nil {
			return err
		}
		var message string
		if err := dec.ReadString(&message); err != nil {
			return err
		}
		return StatusCode(remoteCode)

	default:
		return BadDecodingError
	}

	switch ch.securityMode {
	case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:

		if ch.localPrivateKey == nil {
			return BadSecurityChecksFailed
		}

		if ch.remotePublicKey == nil {
			return BadSecurityChecksFailed
		}

		switch ch.securityPolicyURI {
		case SecurityPolicyURIBasic128Rsa15:
			ch.securityPolicy = new(securityPolicyBasic128Rsa15)

		case SecurityPolicyURIBasic256:
			ch.securityPolicy = new(securityPolicyBasic256)

		case SecurityPolicyURIBasic256Sha256:
			ch.securityPolicy = new(securityPolicyBasic256Sha256)

		case SecurityPolicyURIAes128Sha256RsaOaep:
			ch.securityPolicy = new(securityPolicyAes128Sha256RsaOaep)

		default:
			return BadSecurityPolicyRejected
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
				return BadSecurityChecksFailed
			}
			return nil
		}

	default:
		ch.securityPolicy = new(securityPolicyNone)

	}

	ch.pendingResponseCh = make(chan *serviceOperation, 32)
	ch.pendingResponses = make(map[uint32]*serviceOperation)
	ch.cancellation = make(chan struct{})
	ch.channelID = 0
	ch.tokenID = 0
	ch.sendingTokenID = 0
	ch.receivingTokenID = 0

	go ch.responseWorker()

	var localNonce []byte
	// if ch.securityMode > MessageSecurityModeNone {
	localNonce = getNextNonce(ch.securityPolicy.NonceSize())
	// } else {
	// 	localNonce = []byte{}
	// }
	request := &OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           SecurityTokenRequestTypeIssue,
		SecurityMode:          ch.securityMode,
		ClientNonce:           ByteString(localNonce),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return BadProtocolVersionUnsupported
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
	var request = &CloseSecureChannelRequest{}
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
func (ch *clientSecureChannel) sendRequest(ctx context.Context, op *serviceOperation) error {
	// Check if time to renew security token.
	if !ch.tokenRenewalTime.IsZero() && time.Now().After(ch.tokenRenewalTime) {
		ch.tokenRenewalTime = ch.tokenRenewalTime.Add(60000 * time.Millisecond)
		ch.renewToken(ctx)
	}

	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()

	req := op.Request()

	if ch.trace {
		b, _ := json.Marshal(req)
		log.Printf("%s%s", reflect.TypeOf(req).Elem().Name(), b)

	}

	switch req := req.(type) {
	case *OpenSecureChannelRequest:
		err := ch.sendOpenSecureChannelRequest(ctx, req)
		if err != nil {
			return err
		}
	case *CloseSecureChannelRequest:
		err := ch.sendServiceRequest(ctx, req)
		if err != nil {
			return err
		}
		// send a success response to ourselves (the server will just close it's socket).
		select {
		case op.ResponseCh() <- &CloseSecureChannelResponse{ResponseHeader: ResponseHeader{RequestHandle: req.RequestHandle, Timestamp: time.Now()}}:
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
func (ch *clientSecureChannel) sendOpenSecureChannelRequest(ctx context.Context, request *OpenSecureChannelRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = bytesPool.Get().([]byte)
	defer bytesPool.Put(sendBuffer)

	var bodyEncoder = NewBinaryEncoder(bodyStream, ch)

	if err := bodyEncoder.WriteNodeID(ObjectIDOpenSecureChannelRequestEncodingDefaultBinary); err != nil {
		return BadEncodingError
	}

	if err := bodyEncoder.Encode(request); err != nil {
		return BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return BadEncodingLimitsExceeded
	}

	// write chunks
	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return BadEncodingLimitsExceeded
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
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
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

		var stream = NewWriter(sendBuffer)
		var encoder = NewBinaryEncoder(stream, ch)

		// header
		encoder.WriteUInt32(messageTypeOpenFinal)
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// asymmetric security header
		encoder.WriteString(ch.securityPolicyURI)
		switch ch.securityMode {
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
			encoder.WriteByteArray(ch.localCertificate)
			thumbprint := sha1.Sum(ch.remoteCertificate)
			encoder.WriteByteArray(thumbprint[:])
		default:
			encoder.WriteByteArray(nil)
			encoder.WriteByteArray(nil)
		}

		if plainHeaderSize != int(stream.Len()) {
			return BadEncodingError
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
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
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
			return BadEncodingError
		}

		// sign
		switch ch.securityMode {
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
			signature, err := ch.securityPolicy.RSASign(ch.localPrivateKey, stream.Bytes())
			if err != nil {
				return err
			}
			if len(signature) != signatureSize {
				return BadEncodingError
			}
			_, err = stream.Write(signature)
			if err != nil {
				return err
			}
		}

		// encrypt
		switch ch.securityMode {
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
			var encryptionBuffer = bytesPool.Get().([]byte)
			defer bytesPool.Put(encryptionBuffer)

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
					return BadEncodingError
				}
				copy(encryptionBuffer[jj:], cipherText)
				jj += cipherTextBlockSize
			}
			if jj != chunkSize {
				return BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.Write(encryptionBuffer[:chunkSize])
			if err != nil {
				return err
			}

		default:

			if stream.Len() != chunkSize {
				return BadEncodingError
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
func (ch *clientSecureChannel) sendServiceRequest(ctx context.Context, request ServiceRequest) error {
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var sendBuffer = bytesPool.Get().([]byte)
	defer bytesPool.Put(sendBuffer)

	var bodyEncoder = NewBinaryEncoder(bodyStream, ch)

	var id NodeID
	switch request.(type) {

	// frequent
	case *PublishRequest:
		id = ObjectIDPublishRequestEncodingDefaultBinary
	case *ReadRequest:
		id = ObjectIDReadRequestEncodingDefaultBinary
	case *BrowseRequest:
		id = ObjectIDBrowseRequestEncodingDefaultBinary
	case *BrowseNextRequest:
		id = ObjectIDBrowseNextRequestEncodingDefaultBinary
	case *TranslateBrowsePathsToNodeIDsRequest:
		id = ObjectIDTranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary
	case *WriteRequest:
		id = ObjectIDWriteRequestEncodingDefaultBinary
	case *CallRequest:
		id = ObjectIDCallRequestEncodingDefaultBinary
	case *HistoryReadRequest:
		id = ObjectIDHistoryReadRequestEncodingDefaultBinary

	// moderate
	case *GetEndpointsRequest:
		id = ObjectIDGetEndpointsRequestEncodingDefaultBinary
	case *OpenSecureChannelRequest:
		id = ObjectIDOpenSecureChannelRequestEncodingDefaultBinary
	case *CloseSecureChannelRequest:
		id = ObjectIDCloseSecureChannelRequestEncodingDefaultBinary
	case *CreateSessionRequest:
		id = ObjectIDCreateSessionRequestEncodingDefaultBinary
	case *ActivateSessionRequest:
		id = ObjectIDActivateSessionRequestEncodingDefaultBinary
	case *CloseSessionRequest:
		id = ObjectIDCloseSessionRequestEncodingDefaultBinary
	case *CreateMonitoredItemsRequest:
		id = ObjectIDCreateMonitoredItemsRequestEncodingDefaultBinary
	case *DeleteMonitoredItemsRequest:
		id = ObjectIDDeleteMonitoredItemsRequestEncodingDefaultBinary
	case *CreateSubscriptionRequest:
		id = ObjectIDCreateSubscriptionRequestEncodingDefaultBinary
	case *DeleteSubscriptionsRequest:
		id = ObjectIDDeleteSubscriptionsRequestEncodingDefaultBinary
	case *SetPublishingModeRequest:
		id = ObjectIDSetPublishingModeRequestEncodingDefaultBinary

		// rare
	case *ModifyMonitoredItemsRequest:
		id = ObjectIDModifyMonitoredItemsRequestEncodingDefaultBinary
	case *SetMonitoringModeRequest:
		id = ObjectIDSetMonitoringModeRequestEncodingDefaultBinary
	case *SetTriggeringRequest:
		id = ObjectIDSetTriggeringRequestEncodingDefaultBinary
	case *ModifySubscriptionRequest:
		id = ObjectIDModifySubscriptionRequestEncodingDefaultBinary
	case *RepublishRequest:
		id = ObjectIDRepublishRequestEncodingDefaultBinary
	case *TransferSubscriptionsRequest:
		id = ObjectIDTransferSubscriptionsRequestEncodingDefaultBinary
	case *FindServersRequest:
		id = ObjectIDFindServersRequestEncodingDefaultBinary
	case *FindServersOnNetworkRequest:
		id = ObjectIDFindServersOnNetworkRequestEncodingDefaultBinary
	case *RegisterServerRequest:
		id = ObjectIDRegisterServerRequestEncodingDefaultBinary
	case *RegisterServer2Request:
		id = ObjectIDRegisterServer2RequestEncodingDefaultBinary
	case *CancelRequest:
		id = ObjectIDCancelRequestEncodingDefaultBinary
	case *AddNodesRequest:
		id = ObjectIDAddNodesRequestEncodingDefaultBinary
	case *AddReferencesRequest:
		id = ObjectIDAddReferencesRequestEncodingDefaultBinary
	case *DeleteNodesRequest:
		id = ObjectIDDeleteNodesRequestEncodingDefaultBinary
	case *DeleteReferencesRequest:
		id = ObjectIDDeleteReferencesRequestEncodingDefaultBinary
	case *RegisterNodesRequest:
		id = ObjectIDRegisterNodesRequestEncodingDefaultBinary
	case *UnregisterNodesRequest:
		id = ObjectIDUnregisterNodesRequestEncodingDefaultBinary
	case *QueryFirstRequest:
		id = ObjectIDQueryFirstRequestEncodingDefaultBinary
	case *QueryNextRequest:
		id = ObjectIDQueryNextRequestEncodingDefaultBinary
	case *HistoryUpdateRequest:
		id = ObjectIDHistoryUpdateRequestEncodingDefaultBinary
	default:
		return BadDecodingError
	}

	if err := bodyEncoder.WriteNodeID(id); err != nil {
		return BadEncodingError
	}

	if err := bodyEncoder.Encode(request); err != nil {
		return BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return BadEncodingLimitsExceeded
	}

	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		switch ch.securityMode {
		case MessageSecurityModeSignAndEncrypt:
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

		var stream = NewWriter(sendBuffer)
		var encoder = NewBinaryEncoder(stream, ch)

		// header
		if bodyCount > bodySize {
			encoder.WriteUInt32(messageTypeChunk)
		} else {
			encoder.WriteUInt32(messageTypeFinal)
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
			case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
				// (re)create local security keys for encrypting the next message sent
				localSecurityKey := calculatePSHA(ch.remoteNonce, ch.localNonce, len(ch.localSigningKey)+len(ch.localEncryptingKey)+len(ch.localInitializationVector), ch.securityPolicyURI)
				jj := copy(ch.localSigningKey, localSecurityKey)
				jj += copy(ch.localEncryptingKey, localSecurityKey[jj:])
				copy(ch.localInitializationVector, localSecurityKey[jj:])
				// update signer and encrypter with new symmetric keys
				ch.symSignHMAC = ch.securityPolicy.SymHMACFactory(ch.localSigningKey)
				if ch.securityMode == MessageSecurityModeSignAndEncrypt {
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
		if ch.securityMode == MessageSecurityModeSignAndEncrypt {
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
		case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
			signature, err := ch.symSign(ch.symSignHMAC, stream.Bytes())
			if err != nil {
				return err
			}
			stream.Write(signature)
		}

		// encrypt
		if ch.securityMode == MessageSecurityModeSignAndEncrypt {
			span := stream.Bytes()[plainHeaderSize:]
			if len(span)%ch.symEncryptingBlockCipher.BlockSize() != 0 {
				return BadEncodingError
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
			if ch.errCode == Good {
				if ec, ok := err.(StatusCode); ok {
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
func (ch *clientSecureChannel) readResponse() (ServiceResponse, error) {
	ch.receivingSemaphore.Lock()
	defer ch.receivingSemaphore.Unlock()
	var res ServiceResponse
	var sequenceNum uint32
	var requestID uint32
	var paddingHeaderSize int
	var plainHeaderSize int
	var bodySize int
	var paddingSize int

	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()

	var receiveBuffer = bytesPool.Get().([]byte)
	defer bytesPool.Put(receiveBuffer)

	var bodyDecoder = NewBinaryDecoder(bodyStream, ch)

	// read chunks
	var chunkCount int32
	var isFinal bool

	for !isFinal {
		chunkCount++
		if i := int32(ch.maxChunkCount); i > 0 && chunkCount > i {
			return nil, BadEncodingLimitsExceeded
		}

		count, err := ch.Read(receiveBuffer)
		if err != nil || count == 0 {
			return nil, BadSecureChannelClosed
		}

		var stream = bytes.NewReader(receiveBuffer[0:count])
		var decoder = NewBinaryDecoder(stream, ch)

		var messageType uint32
		if err := decoder.ReadUInt32(&messageType); err != nil {
			return nil, BadDecodingError
		}
		var messageLength uint32
		if err := decoder.ReadUInt32(&messageLength); err != nil {
			return nil, BadDecodingError
		}

		if count != int(messageLength) {
			return nil, BadDecodingError
		}

		switch messageType {
		case messageTypeChunk, messageTypeFinal:
			// header
			var channelID uint32
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, BadDecodingError
			}
			if channelID != ch.channelID {
				return nil, BadTCPSecureChannelUnknown
			}

			// symmetric security header
			var tokenID uint32
			if err := decoder.ReadUInt32(&tokenID); err != nil {
				return nil, BadDecodingError
			}

			// detect new token
			ch.tokenLock.RLock()
			if tokenID != ch.receivingTokenID {
				ch.receivingTokenID = tokenID

				switch ch.securityMode {
				case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
					// (re)create remote security keys for decrypting the next message received that has a new TokenId
					remoteSecurityKey := calculatePSHA(ch.localNonce, ch.remoteNonce, len(ch.remoteSigningKey)+len(ch.remoteEncryptingKey)+len(ch.remoteInitializationVector), ch.securityPolicyURI)
					jj := copy(ch.remoteSigningKey, remoteSecurityKey)
					jj += copy(ch.remoteEncryptingKey, remoteSecurityKey[jj:])
					copy(ch.remoteInitializationVector, remoteSecurityKey[jj:])
					// update verifier and decrypter with new symmetric keys
					ch.symVerifyHMAC = ch.securityPolicy.SymHMACFactory(ch.remoteSigningKey)
					if ch.securityMode == MessageSecurityModeSignAndEncrypt {
						ch.symDecryptingBlockCipher, _ = aes.NewCipher(ch.remoteEncryptingKey)
					}
				}
			}
			ch.tokenLock.RUnlock()

			plainHeaderSize = 16
			// decrypt
			if ch.securityMode == MessageSecurityModeSignAndEncrypt {
				span := receiveBuffer[plainHeaderSize:count]
				if len(span)%ch.symDecryptingBlockCipher.BlockSize() != 0 {
					return nil, BadDecodingError
				}
				cipher.NewCBCDecrypter(ch.symDecryptingBlockCipher, ch.remoteInitializationVector).CryptBlocks(span, span)
			}

			// verify
			switch ch.securityMode {
			case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
				sigStart := count - ch.securityPolicy.SymSignatureSize()
				err := ch.symVerify(ch.symVerifyHMAC, receiveBuffer[:sigStart], receiveBuffer[sigStart:count])
				if err != nil {
					return nil, err
				}
			}

			// read sequence header
			var sequenceNum uint32
			if err := decoder.ReadUInt32(&sequenceNum); err != nil {
				return nil, BadDecodingError
			}
			var requestID uint32
			if err := decoder.ReadUInt32(&requestID); err != nil {
				return nil, BadDecodingError
			}

			// body
			switch ch.securityMode {
			case MessageSecurityModeSignAndEncrypt:
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

			isFinal = messageType == messageTypeFinal

		case messageTypeOpenFinal:
			// header
			var channelID uint32
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, BadDecodingError
			}
			// asymmetric header
			var securityPolicyURI string
			if err := decoder.ReadString(&securityPolicyURI); err != nil {
				return nil, BadDecodingError
			}
			var serverCertificateByteString ByteString
			if err := decoder.ReadByteString(&serverCertificateByteString); err != nil {
				return nil, BadDecodingError
			}
			var clientThumbprint ByteString
			if err := decoder.ReadByteString(&clientThumbprint); err != nil {
				return nil, BadDecodingError
			}
			plainHeaderSize = count - stream.Len()

			// decrypt
			switch ch.securityMode {
			case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
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
			case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
				// verify with remote public key.
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.remotePublicKey.Size()
				err := ch.securityPolicy.RSAVerify(ch.remotePublicKey, receiveBuffer[:sigStart], receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, BadDecodingError
				}
			}

			// sequence header
			if err := decoder.ReadUInt32(&sequenceNum); err != nil {
				return nil, BadDecodingError
			}
			if err := decoder.ReadUInt32(&requestID); err != nil {
				return nil, BadDecodingError
			}

			// body
			switch ch.securityMode {
			case MessageSecurityModeSignAndEncrypt, MessageSecurityModeSign:
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

			isFinal = messageType == messageTypeOpenFinal

		case messageTypeError, messageTypeAbort:
			var statusCode uint32
			if err := decoder.ReadUInt32(&statusCode); err != nil {
				return nil, BadDecodingError
			}
			var message string
			if err := decoder.ReadString(&message); err != nil {
				return nil, BadDecodingError
			}
			ch.errCode = StatusCode(statusCode)
			return nil, StatusCode(statusCode)

		default:
			return nil, BadUnknownResponse
		}

		if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
			return nil, BadEncodingLimitsExceeded
		}
	}

	var nodeID NodeID
	if err := bodyDecoder.ReadNodeID(&nodeID); err != nil {
		return nil, BadDecodingError
	}

	switch nodeID {

	// frequent
	case ObjectIDPublishResponseEncodingDefaultBinary:
		res = new(PublishResponse)
	case ObjectIDReadResponseEncodingDefaultBinary:
		res = new(ReadResponse)
	case ObjectIDBrowseResponseEncodingDefaultBinary:
		res = new(BrowseResponse)
	case ObjectIDBrowseNextResponseEncodingDefaultBinary:
		res = new(BrowseNextResponse)
	case ObjectIDTranslateBrowsePathsToNodeIDsResponseEncodingDefaultBinary:
		res = new(TranslateBrowsePathsToNodeIDsResponse)
	case ObjectIDWriteResponseEncodingDefaultBinary:
		res = new(WriteResponse)
	case ObjectIDCallResponseEncodingDefaultBinary:
		res = new(CallResponse)
	case ObjectIDHistoryReadResponseEncodingDefaultBinary:
		res = new(HistoryReadResponse)

	// moderate
	case ObjectIDGetEndpointsResponseEncodingDefaultBinary:
		res = new(GetEndpointsResponse)
	case ObjectIDOpenSecureChannelResponseEncodingDefaultBinary:
		res = new(OpenSecureChannelResponse)
	case ObjectIDCloseSecureChannelResponseEncodingDefaultBinary:
		res = new(CloseSecureChannelResponse)
	case ObjectIDCreateSessionResponseEncodingDefaultBinary:
		res = new(CreateSessionResponse)
	case ObjectIDActivateSessionResponseEncodingDefaultBinary:
		res = new(ActivateSessionResponse)
	case ObjectIDCloseSessionResponseEncodingDefaultBinary:
		res = new(CloseSessionResponse)
	case ObjectIDCreateMonitoredItemsResponseEncodingDefaultBinary:
		res = new(CreateMonitoredItemsResponse)
	case ObjectIDDeleteMonitoredItemsResponseEncodingDefaultBinary:
		res = new(DeleteMonitoredItemsResponse)
	case ObjectIDCreateSubscriptionResponseEncodingDefaultBinary:
		res = new(CreateSubscriptionResponse)
	case ObjectIDDeleteSubscriptionsResponseEncodingDefaultBinary:
		res = new(DeleteSubscriptionsResponse)
	case ObjectIDSetPublishingModeResponseEncodingDefaultBinary:
		res = new(SetPublishingModeResponse)

		// rare
	case ObjectIDModifyMonitoredItemsResponseEncodingDefaultBinary:
		res = new(ModifyMonitoredItemsResponse)
	case ObjectIDSetMonitoringModeResponseEncodingDefaultBinary:
		res = new(SetMonitoringModeResponse)
	case ObjectIDSetTriggeringResponseEncodingDefaultBinary:
		res = new(SetTriggeringResponse)
	case ObjectIDModifySubscriptionResponseEncodingDefaultBinary:
		res = new(ModifySubscriptionResponse)
	case ObjectIDRepublishResponseEncodingDefaultBinary:
		res = new(RepublishResponse)
	case ObjectIDTransferSubscriptionsResponseEncodingDefaultBinary:
		res = new(TransferSubscriptionsResponse)
	case ObjectIDFindServersResponseEncodingDefaultBinary:
		res = new(FindServersResponse)
	case ObjectIDFindServersOnNetworkResponseEncodingDefaultBinary:
		res = new(FindServersOnNetworkResponse)
	case ObjectIDRegisterServerResponseEncodingDefaultBinary:
		res = new(RegisterServerResponse)
	case ObjectIDRegisterServer2ResponseEncodingDefaultBinary:
		res = new(RegisterServer2Response)
	case ObjectIDCancelResponseEncodingDefaultBinary:
		res = new(CancelResponse)
	case ObjectIDAddNodesResponseEncodingDefaultBinary:
		res = new(AddNodesResponse)
	case ObjectIDAddReferencesResponseEncodingDefaultBinary:
		res = new(AddReferencesResponse)
	case ObjectIDDeleteNodesResponseEncodingDefaultBinary:
		res = new(DeleteNodesResponse)
	case ObjectIDDeleteReferencesResponseEncodingDefaultBinary:
		res = new(DeleteReferencesResponse)
	case ObjectIDRegisterNodesResponseEncodingDefaultBinary:
		res = new(RegisterNodesResponse)
	case ObjectIDUnregisterNodesResponseEncodingDefaultBinary:
		res = new(UnregisterNodesResponse)
	case ObjectIDQueryFirstResponseEncodingDefaultBinary:
		res = new(QueryFirstResponse)
	case ObjectIDQueryNextResponseEncodingDefaultBinary:
		res = new(QueryNextResponse)
	case ObjectIDHistoryUpdateResponseEncodingDefaultBinary:
		res = new(HistoryUpdateResponse)
	default:
		return nil, BadDecodingError
	}

	// decode fields from message stream
	err := bodyDecoder.Decode(res)
	if err != nil {
		return nil, BadDecodingError
	}

	if ch.trace {
		b, _ := json.Marshal(res)
		log.Printf("%s%s", reflect.TypeOf(res).Elem().Name(), b)
	}

	return res, nil
}

// handleResponse directs the response to the correct handler.
func (ch *clientSecureChannel) handleResponse(res ServiceResponse) error {
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
	return BadUnknownResponse
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
	var localNonce []byte
	// if ch.securityMode > MessageSecurityModeNone {
	localNonce = getNextNonce(ch.securityPolicy.NonceSize())
	// } else {
	// 	localNonce = []byte{}
	// }
	request := &OpenSecureChannelRequest{
		ClientProtocolVersion: protocolVersion,
		RequestType:           SecurityTokenRequestTypeRenew,
		SecurityMode:          ch.securityMode,
		ClientNonce:           ByteString(localNonce),
		RequestedLifetime:     ch.tokenRequestedLifetime,
	}
	res, err := ch.Request(ctx, request)
	if err != nil {
		return err
	}
	response := res.(*OpenSecureChannelResponse)
	if response.ServerProtocolVersion < protocolVersion {
		return BadProtocolVersionUnsupported
	}

	ch.tokenLock.Lock()
	ch.tokenRenewalTime = time.Now().Add(time.Duration(response.SecurityToken.RevisedLifetime*75/100) * time.Millisecond)
	// ch.channelId = response.SecurityToken.ChannelID
	ch.tokenID = response.SecurityToken.TokenID
	ch.localNonce = []byte(request.ClientNonce)
	ch.remoteNonce = []byte(response.ServerNonce)
	ch.tokenLock.Unlock()
	return nil
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

// calculatePSHA calculates the pseudo random function.
func calculatePSHA(secret, seed []byte, sizeBytes int, securityPolicyURI string) []byte {
	var mac hash.Hash
	switch securityPolicyURI {
	case SecurityPolicyURIBasic128Rsa15, SecurityPolicyURIBasic256:
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

// Write sends a chunk to the remote endpoint.
func (ch *clientSecureChannel) Write(p []byte) (int, error) {
	return ch.conn.Write(p)
}

// Read receives a chunk from the remote endpoint.
func (ch *clientSecureChannel) Read(p []byte) (int, error) {
	if ch.conn == nil {
		return 0, BadSecureChannelClosed
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
